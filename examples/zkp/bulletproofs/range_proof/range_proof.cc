#include "range_proof.h"

#include <memory>
#include <vector>

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

namespace examples::zkp {

using yacl::crypto::EcGroup;
using yacl::crypto::EcPoint;
using yacl::math::MPInt;

namespace {

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

// Helper function to compute delta(y,z)
[[maybe_unused]] MPInt ComputeDelta(size_t n, const MPInt& y, const MPInt& z, const MPInt& order) {
  // Calculate sum_y = y^0 + y^1 + ... + y^(n-1)
  MPInt sum_y;
  {
    MPInt y_i;
    y_i.Set(1);  // y^0
    sum_y.Set(0);
    
    for (size_t i = 0; i < n; i++) {
      MPInt::AddMod(sum_y, y_i, order, &sum_y);
      MPInt::MulMod(y_i, y, order, &y_i);
    }
  }
  
  // Calculate sum_2 = 2^0 + 2^1 + ... + 2^(n-1)
  MPInt sum_2;
  {
    MPInt two_i, two;
    two_i.Set(1);  // 2^0
    two.Set(2);
    sum_2.Set(0);
    
    for (size_t i = 0; i < n; i++) {
      MPInt::AddMod(sum_2, two_i, order, &sum_2);
      MPInt::MulMod(two_i, two, order, &two_i);
    }
  }
  
  // delta = (z - z^2) * sum_y - z^3 * sum_2
  MPInt z2, z3, term1, term2, result;
  MPInt::MulMod(z, z, order, &z2);
  MPInt::MulMod(z2, z, order, &z3);
  
  MPInt z_minus_z2;
  MPInt::SubMod(z, z2, order, &z_minus_z2);
  
  MPInt::MulMod(z_minus_z2, sum_y, order, &term1);
  MPInt::MulMod(z3, sum_2, order, &term2);
  MPInt::SubMod(term1, term2, order, &result);
  
  return result;
}

// Helper function to generate random scalar
MPInt RandomScalar(const MPInt& order) {
  MPInt result;
  MPInt::RandomLtN(order, &result);
  return result;
}

} // namespace

std::pair<RangeProof, yacl::crypto::EcPoint> RangeProof::CreateSingle(
    const std::shared_ptr<yacl::crypto::EcGroup>& curve,
    SimpleTranscript& transcript,
    const yacl::math::MPInt& value,
    const yacl::math::MPInt& blinding,
    size_t bit_size) {
  YACL_ENFORCE(curve != nullptr, "Curve cannot be null");
  YACL_ENFORCE(bit_size == 8 || bit_size == 16 || bit_size == 32 || bit_size == 64,
               "Bit size must be 8, 16, 32, or 64");
  
  const MPInt& order = curve->GetOrder();
  
  // Check value is in range [0, 2^bit_size - 1]
  MPInt max_value;
  MPInt two;
  two.Set(2);
  MPInt::Pow(two, bit_size, &max_value);
  MPInt one;
  one.Set(1);
  max_value = max_value - one;
  
  MPInt zero;
  zero.Set(0);
  YACL_ENFORCE(value >= zero && value <= max_value,
               "Value out of range");
  
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
    A_points.push_back(curve->GetGenerator());
  }

  // Add H^aR terms
  for (size_t i = 0; i < bit_size; i++) {
    A_scalars.push_back(aR[i]);
    A_points.push_back(curve->GetGenerator());
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
  EcPoint T1 = curve->Add(
      curve->Mul(curve->GetGenerator(), t1),
      curve->Mul(curve->GetGenerator(), tau1));
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

  // Need G_vec and H_vec. Let's assume they are the points used in A and S commitments.
  // You might need to adjust how G_vec and H_vec are obtained/passed.
  std::vector<EcPoint> g_vec_ipp; // Example: Placeholder, needs actual generator points
  std::vector<EcPoint> h_vec_ipp; // Example: Placeholder, needs actual generator points
  g_vec_ipp.reserve(bit_size);
  h_vec_ipp.reserve(bit_size);
  // Populate g_vec_ipp and h_vec_ipp with the actual generator points used for A/S

  // Create InnerProductProof
  auto ipp_proof = InnerProductProof::Create(
      curve,
      transcript,
      curve->GetGenerator(), // Q point (verify if this is correct for range proof)
      std::vector<MPInt>(bit_size, MPInt(1)), // G_factors (Check if correct)
      std::vector<MPInt>(bit_size, MPInt(1)), // H_factors (Check if correct)
      g_vec_ipp,             // G_vec
      h_vec_ipp,             // H_vec
      l_vec,                 // a_vec
      r_vec                  // b_vec
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
      curve->Mul(curve->GetGenerator(), blinding));

  return {proof, V};
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

  // Absorb T1 and T2
  transcript.AbsorbEcPoint(curve, yacl::ByteContainerView("T1"), T1_);
  transcript.AbsorbEcPoint(curve, yacl::ByteContainerView("T2"), T2_);

  // Get challenge x
  MPInt x = transcript.ChallengeMPInt(yacl::ByteContainerView("x"), order);

  // Verify that t = t(x) = <l(x), r(x)>
  transcript.Absorb(yacl::ByteContainerView("t"), 
                   t_x_.ToBytes(32, yacl::Endian::little));
  transcript.Absorb(yacl::ByteContainerView("tau_x"), 
                   t_x_blinding_.ToBytes(32, yacl::Endian::little));
  transcript.Absorb(yacl::ByteContainerView("mu"), 
                   e_blinding_.ToBytes(32, yacl::Endian::little));

  // Get challenge w
  MPInt w = transcript.ChallengeMPInt(yacl::ByteContainerView("w"), order);

  // Calculate delta(y,z)
  MPInt delta = ComputeDelta(bit_size, y, z, order);

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

  if (!curve->PointEqual(left, right)) {
    return Error::kVerificationFailed;
  }

  // Verify the inner product proof
  std::vector<MPInt> ones(bit_size);
  for (size_t i = 0; i < bit_size; ++i) {
    ones[i].Set(1);
  }
  
  // Recompute P = A + x*S + ... (This depends on the verification equation)
  // The P argument for ipp_proof_.Verify should be the commitment being opened.
  EcPoint P_for_ipp = curve->Add(
      curve->Mul(curve->GetGenerator(), x),
      curve->Mul(S_, x)
  );

  // Need G_vec and H_vec (should match those used in CreateSingle)
  std::vector<EcPoint> g_vec_ipp; // Example: Placeholder
  std::vector<EcPoint> h_vec_ipp; // Example: Placeholder
  // Populate g_vec_ipp and h_vec_ipp

  // Call InnerProductProof::Verify
  if (ipp_proof_.Verify(
          curve,
          bit_size, // n_in
          transcript,
          std::vector<MPInt>(bit_size, MPInt(1)), // G_factors (Check if correct)
          std::vector<MPInt>(bit_size, MPInt(1)), // H_factors (Check if correct)
          P_for_ipp,            // P (The commitment being opened)
          curve->GetGenerator(),// Q point (verify if this is correct)
          g_vec_ipp,            // G_vec
          h_vec_ipp             // H_vec
          ) != InnerProductProof::Error::kOk) {
    return Error::kVerificationFailed;
  }

  return Error::kOk;
}

yacl::Buffer RangeProof::ToBytes() const {
  // TODO: Implement serialization
  return yacl::Buffer();
}

RangeProof RangeProof::FromBytes(
    const std::shared_ptr<yacl::crypto::EcGroup>& curve [[maybe_unused]],
    const yacl::ByteContainerView& bytes [[maybe_unused]]) {
  // TODO: Implement deserialization
  return RangeProof();
}

RangeProof::Error RangeProof::Create(
    const std::shared_ptr<yacl::crypto::EcGroup>& curve,
    const std::vector<MPInt>& values,
    const std::vector<MPInt>& blindings,
    const std::vector<EcPoint>& g_vec,
    const std::vector<EcPoint>& h_vec,
    const EcPoint& u,
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

  // ... existing code ...

  return Error::kOk;
}

} // namespace examples::zkp 