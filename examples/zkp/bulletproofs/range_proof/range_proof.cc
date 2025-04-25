#include "range_proof.h"

#include <memory>
#include <vector>
#include <cstring>
#include <cstdint>

#include "yacl/base/buffer.h"
#include "yacl/base/exception.h"
#include "yacl/crypto/ecc/ec_point.h"
#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/math/mpint/mp_int.h"
#include "yacl/utils/parallel.h"
#include "yacl/crypto/hash/hash_utils.h"
#include "yacl/base/int128.h"
#include "fmt/format.h"

#include "../simple_transcript.h"
#include "../inner_product_proof.h"
#include "../generators.h"

namespace examples::zkp {

using yacl::Buffer;
using yacl::crypto::EcGroup;
using yacl::crypto::EcPoint;
using yacl::math::MPInt;

namespace {

// Helper function to generate random scalar
static MPInt RandomScalar(const MPInt& order) {
  MPInt result;
  MPInt::RandomLtN(order, &result);
  return result;
}

// Helper function to compute vector of powers: [2^0, 2^1, ..., 2^(n-1)]
[[maybe_unused]] std::vector<MPInt> PowersOfTwo(size_t n, const MPInt& order) {
  std::vector<MPInt> powers(n);
  MPInt base;
  base.Set(1);
  powers[0] = base;
  
  MPInt two;
  two.Set(2);
  
  for (size_t i = 1; i < n; i++) {
    MPInt::MulMod(powers[i-1], two, order, &powers[i]);
  }
  return powers;
}

// Helper function to compute aL and aR vectors from value
std::vector<MPInt> DecomposeValue(const MPInt& value, size_t n) {
  std::vector<MPInt> bits;
  bits.reserve(n);
  
  for (size_t i = 0; i < n; ++i) {
    MPInt bit;
    bit.Set(value.GetBit(i));
    bits.push_back(bit);
  }
  
  return bits;
}

// Helper function to compute sum of powers efficiently for power of 2
static MPInt SumOfPowers(const MPInt& x, size_t n, const MPInt& order) {
  // If n is 0 or 1, return n directly
  if (n == 0 || n == 1) {
    MPInt result;
    result.Set(n);
    return result;
  }

  // For non-power of 2, use slow method
  if ((n & (n - 1)) != 0) {
    MPInt sum, x_i;
    sum.Set(0);
    x_i.Set(1);
    
    for (size_t i = 0; i < n; i++) {
      MPInt::AddMod(sum, x_i, order, &sum);
      MPInt::MulMod(x_i, x, order, &x_i);
    }
    return sum;
  }

  // Fast method for power of 2
  MPInt result, one;
  one.Set(1);
  MPInt::AddMod(one, x, order, &result);  // result = 1 + x
  
  MPInt factor = x;
  size_t m = n;
  
  while (m > 2) {
    MPInt::MulMod(factor, factor, order, &factor);  // factor = factor * factor
    MPInt temp;
    MPInt::MulMod(factor, result, order, &temp);  // temp = factor * result
    MPInt::AddMod(result, temp, order, &result);  // result = result + temp
    m = m / 2;
  }
  
  return result;
}

} // namespace

std::pair<RangeProof, yacl::crypto::EcPoint> RangeProof::CreateSingle(
    BulletproofGens& bp_gens,
    PedersenGens& pc_gens,
    const std::shared_ptr<yacl::crypto::EcGroup>& curve,
    SimpleTranscript& transcript,
    const yacl::math::MPInt& value,
    const yacl::math::MPInt& blinding,
    size_t bit_size) {
  YACL_ENFORCE(curve != nullptr, "Curve cannot be null");
  YACL_ENFORCE(bit_size == 8 || bit_size == 16 || bit_size == 32 || bit_size == 64,
               "Bit size must be 8, 16, 32, or 64");


  const MPInt& order = curve->GetOrder();
  
  // Generate the generator vectors at the beginning
  auto g_vec = GenerateGenerators(curve, bit_size, "G");
  auto h_vec = GenerateGenerators(curve, bit_size, "H");
  
  // Generate the second generator for Pedersen commitments
  auto h_pedersen = curve->HashToCurve(std::string_view("H_pedersen"));
  
  // Check value is in range [0, 2^bit_size - 1]
  MPInt max_value;
  MPInt two;
  two.Set(2);
  MPInt::Pow(two, bit_size, &max_value);
  MPInt one;
  one.Set(1);
  max_value = max_value - one;
  
  MPInt zero;
  zero.SetZero();
  YACL_ENFORCE(value.Compare(zero) >= 0 && value.Compare(max_value) <= 0,
               "value out of range [0, 2^{} - 1]", bit_size);
  
  // Domain separation
  transcript.Absorb(yacl::ByteContainerView("dom-sep"),
                   yacl::ByteContainerView("range-proof-single"));
  
  // Decompose value into bit vectors
  auto aL = DecomposeValue(value, bit_size);
  
  // Generate random blinding factors
  MPInt alpha = RandomScalar(order);
  MPInt sL = RandomScalar(order);
  MPInt sR = RandomScalar(order);
  MPInt rho = RandomScalar(order);

  // Create aR = aL - 1
  std::vector<MPInt> aR(bit_size);
  for (size_t i = 0; i < bit_size; i++) {
    MPInt one;
    one.Set(1);
    MPInt::SubMod(aL[i], one, order, &aR[i]);
  }

  // 1. Vector commitments
  // Compute A = h^alpha * G^aL * H^aR
  std::vector<MPInt> A_scalars;
  std::vector<EcPoint> A_points;
  A_scalars.reserve(2 * bit_size + 1);
  A_points.reserve(2 * bit_size + 1);

  // Add h^alpha term
  A_scalars.push_back(alpha);
  A_points.push_back(curve->GetGenerator());

  // Add G^aL terms
  for (size_t i = 0; i < bit_size; i++) {
    A_scalars.push_back(aL[i]);
    A_points.push_back(g_vec[i]);
  }

  // Add H^aR terms
  for (size_t i = 0; i < bit_size; i++) {
    A_scalars.push_back(aR[i]);
    A_points.push_back(h_vec[i]);
  }

  EcPoint A = VartimeMultiscalarMul(curve, A_scalars, A_points);
  transcript.AbsorbEcPoint(curve, yacl::ByteContainerView("A"), A);

  // Compute S = h^rho * G^sL * H^sR
  std::vector<MPInt> S_scalars;
  std::vector<EcPoint> S_points;
  S_scalars.reserve(2 * bit_size + 1);
  S_points.reserve(2 * bit_size + 1);

  // Add h^rho term
  S_scalars.push_back(rho);
  S_points.push_back(curve->GetGenerator());

  // Add G^sL terms
  for (size_t i = 0; i < bit_size; i++) {
    S_scalars.push_back(sL);
    S_points.push_back(curve->GetGenerator());
  }

  // Add H^sR terms
  for (size_t i = 0; i < bit_size; i++) {
    S_scalars.push_back(sR);
    S_points.push_back(curve->GetGenerator());
  }

  EcPoint S = VartimeMultiscalarMul(curve, S_scalars, S_points);
  transcript.AbsorbEcPoint(curve, yacl::ByteContainerView("S"), S);

  // Get challenges y, z from transcript
  MPInt y = transcript.ChallengeMPInt(yacl::ByteContainerView("y"), order);
  MPInt z = transcript.ChallengeMPInt(yacl::ByteContainerView("z"), order);

  // 2. Polynomial commitments
  // Compute t(x) = <l(x), r(x)>
  std::vector<MPInt> l_poly = aL;  // l(x) = aL - z*1
  for (auto& li : l_poly) {
    MPInt::SubMod(li, z, order, &li);
  }

  std::vector<MPInt> r_poly = aR;  // r(x) = y^n ○ (aR + z*1 + z^2*2^n)
  MPInt z2;
  MPInt::MulMod(z, z, order, &z2);
  
  std::vector<MPInt> exp_y = PowersOfTwo(bit_size, order);
  for (size_t i = 0; i < bit_size; i++) {
    MPInt temp;
    MPInt::MulMod(z2, exp_y[i], order, &temp);  // z^2 * 2^i
    MPInt::AddMod(r_poly[i], z, order, &r_poly[i]);  // aR + z
    MPInt::AddMod(r_poly[i], temp, order, &r_poly[i]);  // + z^2 * 2^i
    MPInt::MulMod(r_poly[i], y, order, &r_poly[i]);  // multiply by y^i
  }

  // Compute t(x) coefficients
  MPInt t0, t1, t2;
  t0.Set(0);
  t1.Set(0);
  t2.Set(0);

  // t0 = <l_poly, r_poly>
  for (size_t i = 0; i < bit_size; i++) {
    MPInt temp;
    MPInt::MulMod(l_poly[i], r_poly[i], order, &temp);
    MPInt::AddMod(t0, temp, order, &t0);
  }

  // Compute T1 = g^t1 * h^tau1
  MPInt tau1 = RandomScalar(order);
  auto h = curve->HashToCurve("H");  // 使用不同的生成器点
  EcPoint T1 = curve->Add(
      curve->Mul(curve->GetGenerator(), t1),
      curve->Mul(h, tau1));  // 使用不同的生成器
  transcript.AbsorbEcPoint(curve, yacl::ByteContainerView("T1"), T1);

  // Compute T2 = g^t2 * h^tau2
  MPInt tau2 = RandomScalar(order);
  EcPoint T2 = curve->Add(
      curve->Mul(curve->GetGenerator(), t2),
      curve->Mul(curve->GetGenerator(), tau2));
  transcript.AbsorbEcPoint(curve, yacl::ByteContainerView("T2"), T2);

  // Get challenge x from transcript
  MPInt x = transcript.ChallengeMPInt(yacl::ByteContainerView("x"), order);

  // Compute t = t0 + t1*x + t2*x^2
  MPInt t_x;
  {
    MPInt x2;
    MPInt::MulMod(x, x, order, &x2);
    
    MPInt term1, term2;
    MPInt::MulMod(t1, x, order, &term1);
    MPInt::MulMod(t2, x2, order, &term2);
    
    MPInt::AddMod(t0, term1, order, &t_x);
    MPInt::AddMod(t_x, term2, order, &t_x);
  }

  // Compute tau_x = tau2*x^2 + tau1*x + z^2*gamma
  MPInt tau_x;
  {
    MPInt x2;
    MPInt::MulMod(x, x, order, &x2);
    
    MPInt term1, term2;
    MPInt::MulMod(tau2, x2, order, &term1);
    MPInt::MulMod(tau1, x, order, &term2);
    
    MPInt::AddMod(term1, term2, order, &tau_x);
    
    MPInt z2_gamma;
    MPInt::MulMod(z2, blinding, order, &z2_gamma);
    MPInt::AddMod(tau_x, z2_gamma, order, &tau_x);
  }

  // 3. Inner product proof generation
  std::vector<MPInt> l_vec = l_poly;
  std::vector<MPInt> r_vec = r_poly;

  // Generate mu = alpha + rho*x
  MPInt mu;
  MPInt::MulMod(rho, x, order, &mu);
  MPInt::AddMod(alpha, mu, order, &mu);

  // Initialize G_vec and H_vec for the inner product proof
  std::vector<EcPoint> g_vec_ipp = g_vec; // Use the generated g_vec
  std::vector<EcPoint> h_vec_ipp = h_vec; // Use the generated h_vec

  // Create InnerProductProof
  auto ipp_proof = InnerProductProof::Create(
      curve,
      transcript,
      curve->GetGenerator(),
      [&]() {
        std::vector<MPInt> ones(bit_size);
        for (auto& one : ones) {
          one.Set(1);
        }
        return ones;
      }(),
      [&]() {
        std::vector<MPInt> ones(bit_size);
        for (auto& one : ones) {
          one.Set(1);
        }
        return ones;
      }(),
      g_vec_ipp,
      h_vec_ipp,
      l_vec,
      r_vec
  );

  // 4. Final proof assembly
  RangeProof proof;
  proof.A_ = A;
  proof.S_ = S;
  proof.T1_ = T1;
  proof.T2_ = T2;
  proof.t_x_ = t_x;
  proof.t_x_blinding_ = tau_x;
  proof.e_blinding_ = mu;
  proof.ipp_proof_ = ipp_proof;

  // Compute the Pedersen commitment V = g^v * h^gamma
  EcPoint V = curve->Add(
      curve->Mul(curve->GetGenerator(), value),
      curve->Mul(h_pedersen, blinding));  // Use h_pedersen instead of redefining h

  // 返回proof和commitment
  return std::make_pair(std::move(proof), std::move(V));
}

RangeProof::Error RangeProof::VerifySingle(
    const std::shared_ptr<yacl::crypto::EcGroup>& curve,
    SimpleTranscript& transcript,
    const yacl::crypto::EcPoint& V,
    size_t bit_size) const {



  if (!curve) {
    return Error::kInvalidArgument;
  }

  if (bit_size != 8 && bit_size != 16 && bit_size != 32 && bit_size != 64) {
    return Error::kInvalidArgument;
  }

  // Domain separation
  transcript.Absorb(yacl::ByteContainerView("dom-sep"),
                   yacl::ByteContainerView("range-proof-single"));

  // Absorb the commitment V
  transcript.AbsorbEcPoint(curve, yacl::ByteContainerView("V"), V);

  // Absorb A and S
  transcript.AbsorbEcPoint(curve, yacl::ByteContainerView("A"), A_);
  transcript.AbsorbEcPoint(curve, yacl::ByteContainerView("S"), S_);

  // Get challenges y and z
  const MPInt& order = curve->GetOrder();
  MPInt y = transcript.ChallengeMPInt(yacl::ByteContainerView("y"), order);
  MPInt z = transcript.ChallengeMPInt(yacl::ByteContainerView("z"), order);

  auto zz = z * z;
  auto minus_z = -z;

  // Absorb T1 and T2
  transcript.AbsorbEcPoint(curve, yacl::ByteContainerView("T1"), T1_);
  transcript.AbsorbEcPoint(curve, yacl::ByteContainerView("T2"), T2_);

  // Get challenge x
  MPInt x = transcript.ChallengeMPInt(yacl::ByteContainerView("x"), order);

  // Verify that t = t(x) = <l(x), r(x)>
  transcript.AbsorbScalar(yacl::ByteContainerView("t"), t_x_);
  transcript.AbsorbScalar(yacl::ByteContainerView("tau_x"), t_x_blinding_);
  transcript.AbsorbScalar(yacl::ByteContainerView("mu"), e_blinding_);

  // Get challenge w
  MPInt w = transcript.ChallengeMPInt(yacl::ByteContainerView("w"), order);

  // Calculate delta(y,z)
  MPInt delta = RangeProof::ComputeDelta(bit_size, bit_size, y, z, order);

  // Compute the verification equation
  // g^t = V^z^2 * g^delta * T1^x * T2^x^2
  MPInt z2;
  MPInt::MulMod(z, z, order, &z2);

  MPInt x2;
  MPInt::MulMod(x, x, order, &x2);

  std::vector<MPInt> scalars;
  std::vector<EcPoint> points;
  scalars.reserve(4);
  points.reserve(4);

  // V^z^2 term
  scalars.push_back(z2);
  points.push_back(V);

  // g^delta term
  scalars.push_back(delta);
  points.push_back(curve->GetGenerator());

  // T1^x term
  scalars.push_back(x);
  points.push_back(T1_);

  // T2^x^2 term
  scalars.push_back(x2);
  points.push_back(T2_);

  EcPoint right = VartimeMultiscalarMul(curve, scalars, points);
  EcPoint left = curve->Mul(curve->GetGenerator(), t_x_);

  //debug
  std::cout << "========================Verify left==============================" << std::endl;
  std::cout << curve->SerializePoint(left) << std::endl;
  std::cout << "========================Verify right==============================" << std::endl;
  std::cout << curve->SerializePoint(right) << std::endl;

  //debug
  std::cout << "========================Verify PointEqual==============================" << std::endl;
  if (!curve->PointEqual(left, right)) {
    return Error::kVerificationFailed;
  }

  //debug
  std::cout << "========================Verify inner product proof==============================" << std::endl;
  
  // Verify the inner product proof
  std::vector<MPInt> ones(bit_size);
  for (size_t i = 0; i < bit_size; ++i) {
    ones[i].Set(1);
  }
  
  // Recompute P = A + x*S + ... (This depends on the verification equation)
  // The P argument for ipp_proof_.Verify should be the commitment being opened.
  EcPoint P_for_ipp = curve->Add(
      A_,
      curve->Mul(S_, x)
  );

  // Get the generator vectors for verification
  auto g_vec_ipp = GenerateGenerators(curve, bit_size, "G");
  auto h_vec_ipp = GenerateGenerators(curve, bit_size, "H");

  //debug
  std::cout << "========================ipp_proof_.Verify==============================" << std::endl;
  // Call InnerProductProof::Verify
  if (ipp_proof_.Verify(
          curve,
          bit_size,
          transcript,
          [&]() {
            std::vector<MPInt> ones(bit_size);
            for (auto& one : ones) {
              one.Set(1);
            }
            return ones;
          }(),
          [&]() {
            std::vector<MPInt> ones(bit_size);
            for (auto& one : ones) {
              one.Set(1);
            }
            return ones;
          }(),
          P_for_ipp,
          curve->GetGenerator(),
          g_vec_ipp,
          h_vec_ipp
          ) != InnerProductProof::Error::kOk) {
    return Error::kVerificationFailed;
  }

  return Error::kOk;
}

// 在 range_proof.cc 文件中添加这两个函数的实现

yacl::Buffer RangeProof::ToBytes(const std::shared_ptr<yacl::crypto::EcGroup>& curve) const {
  // 1. 首先计算总大小
  size_t total_size = 0;
  
  // A_ 序列化大小
  auto A_bytes = curve->SerializePoint(A_);
  total_size += sizeof(size_t) + A_bytes.size();
  
  // S_ 序列化大小
  auto S_bytes = curve->SerializePoint(S_);
  total_size += sizeof(size_t) + S_bytes.size();
  
  // T1_ 序列化大小
  auto T1_bytes = curve->SerializePoint(T1_);
  total_size += sizeof(size_t) + T1_bytes.size();
  
  // T2_ 序列化大小
  auto T2_bytes = curve->SerializePoint(T2_);
  total_size += sizeof(size_t) + T2_bytes.size();
  
  // t_x_ 序列化大小
  auto t_bytes = t_x_.Serialize();
  total_size += sizeof(size_t) + t_bytes.size();
  
  // t_x_blinding_ 序列化大小
  auto t_blinding_bytes = t_x_blinding_.Serialize();
  total_size += sizeof(size_t) + t_blinding_bytes.size();
  
  // e_blinding_ 序列化大小
  auto e_blinding_bytes = e_blinding_.Serialize();
  total_size += sizeof(size_t) + e_blinding_bytes.size();
  
  // 2. 分配缓冲区
  yacl::Buffer result(total_size);
  size_t offset = 0;
  
  // 3. 写入数据
  // A_
  auto* ptr = result.data<uint8_t>();
  size_t size = A_bytes.size();
  std::memcpy(ptr + offset, &size, sizeof(size_t));
  offset += sizeof(size_t);
  std::memcpy(ptr + offset, A_bytes.data(), size);
  offset += size;
  
  // S_
  size = S_bytes.size();
  std::memcpy(ptr + offset, &size, sizeof(size_t));
  offset += sizeof(size_t);
  std::memcpy(ptr + offset, S_bytes.data(), size);
  offset += size;
  
  // T1_
  size = T1_bytes.size();
  std::memcpy(ptr + offset, &size, sizeof(size_t));
  offset += sizeof(size_t);
  std::memcpy(ptr + offset, T1_bytes.data(), size);
  offset += size;
  
  // T2_
  size = T2_bytes.size();
  std::memcpy(ptr + offset, &size, sizeof(size_t));
  offset += sizeof(size_t);
  std::memcpy(ptr + offset, T2_bytes.data(), size);
  offset += size;
  
  // t_x_
  size = t_bytes.size();
  std::memcpy(ptr + offset, &size, sizeof(size_t));
  offset += sizeof(size_t);
  std::memcpy(ptr + offset, t_bytes.data(), size);
  offset += size;
  
  // t_x_blinding_
  size = t_blinding_bytes.size();
  std::memcpy(ptr + offset, &size, sizeof(size_t));
  offset += sizeof(size_t);
  std::memcpy(ptr + offset, t_blinding_bytes.data(), size);
  offset += size;
  
  // e_blinding_
  size = e_blinding_bytes.size();
  std::memcpy(ptr + offset, &size, sizeof(size_t));
  offset += sizeof(size_t);
  std::memcpy(ptr + offset, e_blinding_bytes.data(), size);
  offset += size;
  
  return result;
}

RangeProof RangeProof::FromBytes(
    const std::shared_ptr<yacl::crypto::EcGroup>& curve,
    const yacl::ByteContainerView& bytes) {
  
  if (bytes.size() == 0) {
    throw yacl::Exception("Cannot deserialize empty data");
  }
  
  const uint8_t* data = bytes.data();
  size_t offset = 0;
  
  // 1. 解析椭圆曲线上的点
  // A_
  size_t A_size;
  if (offset + sizeof(size_t) > bytes.size()) {
    throw yacl::Exception("Insufficient data for A point size");
  }
  std::memcpy(&A_size, data + offset, sizeof(size_t));
  offset += sizeof(size_t);
  
  if (offset + A_size > bytes.size()) {
    throw yacl::Exception("Insufficient data for A point");
  }
  yacl::Buffer A_bytes(A_size);
  std::memcpy(A_bytes.data(), data + offset, A_size);
  yacl::crypto::EcPoint A = curve->DeserializePoint(A_bytes);
  offset += A_size;
  
  // S_
  size_t S_size;
  if (offset + sizeof(size_t) > bytes.size()) {
    throw yacl::Exception("Insufficient data for S point size");
  }
  std::memcpy(&S_size, data + offset, sizeof(size_t));
  offset += sizeof(size_t);
  
  if (offset + S_size > bytes.size()) {
    throw yacl::Exception("Insufficient data for S point");
  }
  yacl::Buffer S_bytes(S_size);
  std::memcpy(S_bytes.data(), data + offset, S_size);
  yacl::crypto::EcPoint S = curve->DeserializePoint(S_bytes);
  offset += S_size;
  
  // T1_
  size_t T1_size;
  if (offset + sizeof(size_t) > bytes.size()) {
    throw yacl::Exception("Insufficient data for T1 point size");
  }
  std::memcpy(&T1_size, data + offset, sizeof(size_t));
  offset += sizeof(size_t);
  
  if (offset + T1_size > bytes.size()) {
    throw yacl::Exception("Insufficient data for T1 point");
  }
  yacl::Buffer T1_bytes(T1_size);
  std::memcpy(T1_bytes.data(), data + offset, T1_size);
  yacl::crypto::EcPoint T1 = curve->DeserializePoint(T1_bytes);
  offset += T1_size;
  
  // T2_
  size_t T2_size;
  if (offset + sizeof(size_t) > bytes.size()) {
    throw yacl::Exception("Insufficient data for T2 point size");
  }
  std::memcpy(&T2_size, data + offset, sizeof(size_t));
  offset += sizeof(size_t);
  
  if (offset + T2_size > bytes.size()) {
    throw yacl::Exception("Insufficient data for T2 point");
  }
  yacl::Buffer T2_bytes(T2_size);
  std::memcpy(T2_bytes.data(), data + offset, T2_size);
  yacl::crypto::EcPoint T2 = curve->DeserializePoint(T2_bytes);
  offset += T2_size;
  
  // 2. 解析标量值
  // t_x_
  size_t t_size;
  if (offset + sizeof(size_t) > bytes.size()) {
    throw yacl::Exception("Insufficient data for t scalar size");
  }
  std::memcpy(&t_size, data + offset, sizeof(size_t));
  offset += sizeof(size_t);
  
  if (offset + t_size > bytes.size()) {
    throw yacl::Exception("Insufficient data for t scalar");
  }
  yacl::Buffer t_bytes(t_size);
  std::memcpy(t_bytes.data(), data + offset, t_size);
  yacl::math::MPInt t;
  t.Deserialize(t_bytes);
  offset += t_size;
  
  // t_x_blinding_
  size_t t_blinding_size;
  if (offset + sizeof(size_t) > bytes.size()) {
    throw yacl::Exception("Insufficient data for t_blinding scalar size");
  }
  std::memcpy(&t_blinding_size, data + offset, sizeof(size_t));
  offset += sizeof(size_t);
  
  if (offset + t_blinding_size > bytes.size()) {
    throw yacl::Exception("Insufficient data for t_blinding scalar");
  }
  yacl::Buffer t_blinding_bytes(t_blinding_size);
  std::memcpy(t_blinding_bytes.data(), data + offset, t_blinding_size);
  yacl::math::MPInt t_blinding;
  t_blinding.Deserialize(t_blinding_bytes);
  offset += t_blinding_size;
  
  // e_blinding_
  size_t e_blinding_size;
  if (offset + sizeof(size_t) > bytes.size()) {
    throw yacl::Exception("Insufficient data for e_blinding scalar size");
  }
  std::memcpy(&e_blinding_size, data + offset, sizeof(size_t));
  offset += sizeof(size_t);
  
  if (offset + e_blinding_size > bytes.size()) {
    throw yacl::Exception("Insufficient data for e_blinding scalar");
  }
  yacl::Buffer e_blinding_bytes(e_blinding_size);
  std::memcpy(e_blinding_bytes.data(), data + offset, e_blinding_size);
  yacl::math::MPInt e_blinding;
  e_blinding.Deserialize(e_blinding_bytes);
  offset += e_blinding_size;
  
  // 创建并返回 RangeProof 对象
  RangeProof proof;
  proof.A_ = A;
  proof.S_ = S;
  proof.T1_ = T1;
  proof.T2_ = T2;
  proof.t_x_ = t;
  proof.t_x_blinding_ = t_blinding;
  proof.e_blinding_ = e_blinding;
  
  return proof;
}

RangeProof::Error RangeProof::Create(
    const std::shared_ptr<yacl::crypto::EcGroup>& curve,
    const std::vector<MPInt>& values,
    const std::vector<MPInt>& blindings,
    const std::vector<EcPoint>& g_vec,
    const std::vector<EcPoint>& h_vec,
    const EcPoint& u,
    size_t bit_size,
    RangeProof* proof) {
  size_t n = values.size();
  if (n == 0 || n != blindings.size()) {
    return Error::kInvalidInputSize;
  }

  size_t m = g_vec.size();
  if (m == 0 || m != h_vec.size()) {
    return Error::kInvalidInputSize;
  }

  YACL_ENFORCE(curve != nullptr, "Curve cannot be null");
  const MPInt& order = curve->GetOrder();

  // Initialize vectors for A and S calculations
  std::vector<MPInt> A_scalars;
  std::vector<EcPoint> A_points;
  A_scalars.reserve(2 * n);
  A_points.reserve(2 * n);

  // Generate aL and aR vectors
  std::vector<MPInt> aL;
  std::vector<MPInt> aR;
  aL.reserve(n);
  aR.reserve(n);

  for (size_t i = 0; i < n; ++i) {
    aL.push_back(values[i]);
    aR.push_back(blindings[i]);
  }

  // Generate random blinding factors
  MPInt alpha;
  MPInt::RandomLtN(order, &alpha);
  MPInt sL;
  MPInt::RandomLtN(order, &sL);
  MPInt sR;
  MPInt::RandomLtN(order, &sR);
  MPInt rho;
  MPInt::RandomLtN(order, &rho);

  // Calculate points A and S using cyclic access to g_vec and h_vec
  EcPoint A = curve->Mul(h_vec[0], alpha);
  EcPoint S = curve->Mul(h_vec[0], rho);

  for (size_t i = 0; i < n; ++i) {
    EcPoint term_g = curve->Mul(g_vec[i % m], aL[i]);
    EcPoint term_h = curve->Mul(h_vec[i % m], aR[i]);
    A = curve->Add(A, curve->Add(term_g, term_h));

    EcPoint term_sL = curve->Mul(g_vec[i % m], sL);
    EcPoint term_sR = curve->Mul(h_vec[i % m], sR);
    S = curve->Add(S, curve->Add(term_sL, term_sR));
  }

  // Initialize MPInt values
  MPInt zero;
  zero.SetZero();
  MPInt one;
  one.Set(1);
  MPInt two;
  two.Set(2);

  YACL_ENFORCE(values.size() == blindings.size(), 
               "values size {} != blindings size {}", 
                values.size(), blindings.size());
  YACL_ENFORCE(g_vec.size() == h_vec.size(),
               "g_vec size {} != h_vec size {}", 
                g_vec.size(), h_vec.size());
  
  MPInt max_value;
  MPInt::Pow(two, bit_size, &max_value);
  MPInt::SubMod(max_value, one, order, &max_value);
  
  for (const auto& value : values) {
    YACL_ENFORCE(value.Compare(zero) >= 0 && value.Compare(max_value) <= 0,
                 "value out of range [0, 2^{} - 1]", bit_size);
  }

  // TODO: Complete the implementation of the multi-value Create function
  // This likely involves similar steps to CreateSingle but aggregated
  // - Transcript handling for multiple values
  // - Polynomial construction for multiple values
  // - Inner product proof for aggregated vectors
  YACL_ENFORCE(proof != nullptr, "Output proof pointer cannot be null");
  // proof->A_ = A; // Assign calculated values to the output proof object
  // proof->S_ = S;
  // ... and so on for T1, T2, t_x, tau_x, mu, ipp_proof

  return Error::kOk; // Placeholder
}

MPInt RangeProof::ComputeDelta(size_t n, size_t m, const MPInt& y, const MPInt& z, const MPInt& order) {
  // Calculate sum_y = y^0 + y^1 + ... + y^(n*m-1)
  MPInt sum_y = SumOfPowers(y, n * m, order);
  
  // Calculate sum_2 = 2^0 + 2^1 + ... + 2^(n-1)
  MPInt two;
  two.Set(2);
  MPInt sum_2 = SumOfPowers(two, n, order);
  
  // Calculate sum_z = z^0 + z^1 + ... + z^(m-1)
  MPInt sum_z = SumOfPowers(z, m, order);
  
  // Calculate delta = (z - z^2) * sum_y - z^3 * sum_2 * sum_z
  MPInt z2, z3, term1, term2, result;
  MPInt::MulMod(z, z, order, &z2);  // z^2
  MPInt::MulMod(z2, z, order, &z3);  // z^3
  
  MPInt z_minus_z2;
  MPInt::SubMod(z, z2, order, &z_minus_z2);  // z - z^2
  
  MPInt::MulMod(z_minus_z2, sum_y, order, &term1);  // (z - z^2) * sum_y
  
  MPInt temp;
  MPInt::MulMod(sum_2, sum_z, order, &temp);  // sum_2 * sum_z
  MPInt::MulMod(z3, temp, order, &term2);  // z^3 * sum_2 * sum_z
  
  MPInt::SubMod(term1, term2, order, &result);  // term1 - term2
  
  return result;
}

} // namespace examples::zkp 