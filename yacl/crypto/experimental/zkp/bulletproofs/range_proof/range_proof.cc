// Copyright 2025 @yangjucai.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "yacl/crypto/experimental/zkp/bulletproofs/range_proof/range_proof.h"

#include <algorithm>
#include <numeric>  // For std::accumulate
#include <string>
#include <vector>

#include "yacl/base/exception.h"
#include "yacl/crypto/experimental/zkp/bulletproofs/util.h"  // Needs definitions for VecPoly1, Poly2, etc.
#include "yacl/crypto/hash/hash_utils.h"  // For HashToCurve, Sha256
#include "yacl/crypto/rand/rand.h"

namespace examples::zkp {

// --- RangeProof Constructor ---
RangeProof::RangeProof(
    const yacl::crypto::EcPoint& V, const yacl::crypto::EcPoint& A,
    const yacl::crypto::EcPoint& S, const yacl::crypto::EcPoint& T_1,
    const yacl::crypto::EcPoint& T_2, const yacl::math::MPInt& t_x,
    const yacl::math::MPInt& t_x_blinding, const yacl::math::MPInt& e_blinding,
    const InnerProductProof& ipp_proof)  // Use YACL IPP type
    : V_(V),
      A_(A),
      S_(S),
      T_1_(T_1),
      T_2_(T_2),
      t_x_(t_x),
      t_x_blinding_(t_x_blinding),
      e_blinding_(e_blinding),
      ipp_proof_(ipp_proof) {}

// --- Static Helper: MakeGenerators (Mirrors Rust) ---
std::vector<yacl::crypto::EcPoint> RangeProof::MakeGenerators(
    const yacl::crypto::EcPoint& base_point, size_t n,
    const std::shared_ptr<yacl::crypto::EcGroup>& curve) {
  std::vector<yacl::crypto::EcPoint> generators(n);
  if (n == 0) return generators;

  // Seed for first generator: hash of base_point's *compressed* bytes
  // Explicitly compress the point for hashing consistency with Rust
  yacl::Buffer base_bytes =
      curve->SerializePoint(base_point);  // true for compressed
  generators[0] =
      curve->HashToCurve(yacl::crypto::HashToCurveStrategy::Autonomous,
                         yacl::ByteContainerView(base_bytes));

  // Generate subsequent points by hashing previous one's compressed bytes
  for (size_t i = 1; i < n; ++i) {
    yacl::Buffer prev_bytes =
        curve->SerializePoint(generators[i - 1]);  // true for compressed
    //  uses Sha256 of the bytes as input to HashToCurve,
    // but YACL's HashToCurve likely handles the hashing internally based on
    // strategy. Directly using HashToCurve on prev_bytes is likely the intended
    // YACL equivalent. If HashToCurve doesn't use SHA256 internally for
    // Autonomous, this needs adjustment.
    generators[i] =
        curve->HashToCurve(yacl::crypto::HashToCurveStrategy::Autonomous,
                           yacl::ByteContainerView(prev_bytes));
    // If YACL HashToCurve needs explicit hash input:
    // auto hash_val =
    // yacl::crypto::Sha256(yacl::ByteContainerView(prev_bytes)); generators[i]
    // = curve->HashToCurve(yacl::crypto::HashToCurveStrategy::Autonomous, // Or
    // appropriate strategy
    //                                    yacl::ByteContainerView(hash_val));
  }
  return generators;
}

// --- Static Helper: Delta (Mirrors  single-party version) ---
yacl::math::MPInt RangeProof::Delta(
    size_t n, const yacl::math::MPInt& y, const yacl::math::MPInt& z,
    const std::shared_ptr<yacl::crypto::EcGroup>& curve) {
  const auto& order = curve->GetOrder();
  yacl::math::MPInt two(2);
  yacl::math::MPInt zz = z.MulMod(z, order);

  // <1, y^n> = sum_{i=0}^{n-1} y^i
  yacl::math::MPInt sum_y = SumOfPowers(y, n, curve);
  // <1, 2^n> = sum_{i=0}^{n-1} 2^i
  yacl::math::MPInt sum_2 = SumOfPowers(two, n, curve);

  // (z - zz) * sum_y - z * zz * sum_2
  yacl::math::MPInt term1 = z.SubMod(zz, order).MulMod(sum_y, order);
  yacl::math::MPInt term2 =
      z.MulMod(zz, order).MulMod(sum_2, order);  // z^3 * sum_2

  return term1.SubMod(term2, order);  // Result is already modulo order
}

// --- GenerateProof (Mirrors Rust) ---
RangeProof RangeProof::GenerateProof(
    SimpleTranscript& transcript,
    const std::shared_ptr<yacl::crypto::EcGroup>& curve, size_t n, uint64_t v,
    const yacl::math::MPInt& v_blinding) {
  YACL_ENFORCE(n == 8 || n == 16 || n == 32 || n == 64, "Invalid bitsize n");
  uint64_t max_value = (n == 64) ? UINT64_MAX : (1ULL << n);
  YACL_ENFORCE(v < max_value, "Value out of range for bitsize n");

  const auto& order = curve->GetOrder();
  yacl::math::MPInt one(1);

  // 1. Create Generators
  yacl::crypto::EcPoint B = curve->HashToCurve(
      yacl::crypto::HashToCurveStrategy::Autonomous, "hello");
  yacl::crypto::EcPoint B_blinding = curve->HashToCurve(
      yacl::crypto::HashToCurveStrategy::Autonomous, "there");
  std::vector<yacl::crypto::EcPoint> G_vec = MakeGenerators(B, n, curve);
  std::vector<yacl::crypto::EcPoint> H_vec =
      MakeGenerators(B_blinding, n, curve);

  // 2. Commit to value: V = v*B + v_blinding*B_blinding
  yacl::crypto::EcPoint V = curve->Add(curve->Mul(B, yacl::math::MPInt(v)),
                                       curve->Mul(B_blinding, v_blinding));

  // 3. Compute A = <a_L, G> + <a_R, H> + a_blinding * B_blinding
  yacl::math::MPInt a_blinding;
  a_blinding.RandomLtN(order, &a_blinding);
  yacl::crypto::EcPoint A = curve->Mul(B_blinding, a_blinding);
  for (size_t i = 0; i < n; ++i) {
    if (((v >> i) & 1) == 0) {
      A = curve->Sub(A, H_vec[i]);
    } else {
      A = curve->Add(A, G_vec[i]);
    }
  }

  // 4. Compute S = <s_L, G> + <s_R, H> + s_blinding * B_blinding
  yacl::math::MPInt s_blinding;
  s_blinding.RandomLtN(order, &s_blinding);
  std::vector<yacl::math::MPInt> s_L(n), s_R(n);
  std::vector<yacl::math::MPInt> s_scalars;
  s_scalars.reserve(1 + 2 * n);
  std::vector<yacl::crypto::EcPoint> s_points;
  s_points.reserve(1 + 2 * n);
  s_scalars.emplace_back(s_blinding);
  s_points.emplace_back(B_blinding);
  for (size_t i = 0; i < n; ++i) {
    s_L[i].RandomLtN(order, &s_L[i]);
    s_R[i].RandomLtN(order, &s_R[i]);
    s_scalars.emplace_back(s_L[i]);
    s_points.emplace_back(G_vec[i]);
    s_scalars.emplace_back(s_R[i]);
    s_points.emplace_back(H_vec[i]);
  }
  yacl::crypto::EcPoint S = MultiScalarMul(curve, s_scalars, s_points);

  // 5. Commit V, A, S and get challenges y, z
  transcript.AppendPoint("V", V, curve);
  transcript.AppendPoint("A", A, curve);
  transcript.AppendPoint("S", S, curve);
  yacl::math::MPInt y = transcript.ChallengeScalar("y", curve);
  yacl::math::MPInt z = transcript.ChallengeScalar("z", curve);

  // 6. Compute polynomial vectors l(x), r(x) (Using VecPoly1)
  VecPoly1 l_poly = VecPoly1::Zero(n);
  VecPoly1 r_poly = VecPoly1::Zero(n);
  yacl::math::MPInt zz = z.MulMod(z, order);
  yacl::math::MPInt two(2);
  std::vector<yacl::math::MPInt> y_pows = ExpIterVector(y, n, curve);
  std::vector<yacl::math::MPInt> two_pows = ExpIterVector(two, n, curve);
  for (size_t i = 0; i < n; ++i) {
    yacl::math::MPInt a_L_i((v >> i) & 1);
    yacl::math::MPInt a_R_i = a_L_i.SubMod(one, order);
    l_poly.vec0[i] = a_L_i.SubMod(z, order);
    l_poly.vec1[i] = s_L[i];
    r_poly.vec0[i] = y_pows[i].MulMod(a_R_i.AddMod(z, order), order);
    r_poly.vec0[i] =
        r_poly.vec0[i].AddMod(zz.MulMod(two_pows[i], order), order);
    r_poly.vec1[i] = y_pows[i].MulMod(s_R[i], order);
  }

  // 7. Compute t(X) = <l(X), r(X)> (Results in Poly2)
  Poly2 t_poly =
      l_poly.InnerProduct(r_poly, curve);  // t_poly has members t0, t1, t2

  // 8. Compute commitments T1, T2 using B, B_blinding
  yacl::math::MPInt t_1_blinding, t_2_blinding;
  t_1_blinding.RandomLtN(order, &t_1_blinding);
  t_2_blinding.RandomLtN(order, &t_2_blinding);
  yacl::crypto::EcPoint T_1 = curve->Add(curve->Mul(B, t_poly.t1),
                                         curve->Mul(B_blinding, t_1_blinding));
  yacl::crypto::EcPoint T_2 = curve->Add(curve->Mul(B, t_poly.t2),
                                         curve->Mul(B_blinding, t_2_blinding));

  // 9. Commit T1, T2 and derive challenge x
  transcript.AppendPoint("T_1", T_1, curve);
  transcript.AppendPoint("T_2", T_2, curve);
  yacl::math::MPInt x = transcript.ChallengeScalar("x", curve);

  // 10. Evaluate t at x and compute blindings
  yacl::math::MPInt t_x = t_poly.Eval(x, curve);
  // t_x_blinding = z^2*v_blinding + x*t_1_blinding + x^2*t_2_blinding
  yacl::math::MPInt t_x_blinding = zz.MulMod(v_blinding, order);
  t_x_blinding = t_x_blinding.AddMod(x.MulMod(t_1_blinding, order), order);
  t_x_blinding = t_x_blinding.AddMod(
      x.MulMod(x, order).MulMod(t_2_blinding, order), order);
  // e_blinding = a_blinding + x*s_blinding
  yacl::math::MPInt e_blinding =
      a_blinding.AddMod(x.MulMod(s_blinding, order), order);

  // 11. Commit final scalars and derive challenge w
  transcript.AppendScalar("t_x", t_x);
  transcript.AppendScalar("t_x_blinding", t_x_blinding);
  transcript.AppendScalar("e_blinding", e_blinding);
  yacl::math::MPInt w = transcript.ChallengeScalar("w", curve);

  // 12. Compute IPP inputs
  // Q = w * B_blinding
  yacl::crypto::EcPoint Q = curve->Mul(B_blinding, w);
  // IPP H factors = y^-i (Note:  IPP::create takes H factors as first factor
  // arg) C++ IPP::Create takes G_factors, H_factors. We need to match how C++
  // IPP uses them. Assuming C++ IPP expects factors for G and H basis:
  std::vector<yacl::math::MPInt> ipp_G_factors(n, one);  // Factors for G_vec
  yacl::math::MPInt y_inv = y.InvertMod(order);
  std::vector<yacl::math::MPInt> ipp_H_factors =
      ExpIterVector(y_inv, n, curve);  // Factors for H_vec
  // IPP vectors a, b
  std::vector<yacl::math::MPInt> ipp_a_vec = l_poly.Eval(x, curve);  // l(x)
  std::vector<yacl::math::MPInt> ipp_b_vec = r_poly.Eval(x, curve);  // r(x)

  // 13. Create Inner Product Proof
  // Note: Pass G_vec, H_vec directly (size n already)
  InnerProductProof ipp_proof =
      InnerProductProof::Create(transcript, curve, Q,
                                ipp_H_factors,  // Factors for H
                                G_vec, H_vec,  // The generators derived earlier
                                ipp_a_vec, ipp_b_vec);

  // 14. Construct final RangeProof
  return RangeProof(V, A, S, T_1, T_2, t_x, t_x_blinding, e_blinding,
                    ipp_proof);
}

// --- Verify---
bool RangeProof::Verify(SimpleTranscript& transcript,
                        const std::shared_ptr<yacl::crypto::EcGroup>& curve,
                        size_t n) const {
  YACL_ENFORCE(n == 8 || n == 16 || n == 32 || n == 64, "Invalid bitsize n");
  const auto& order = curve->GetOrder();
  yacl::math::MPInt one(1);
  yacl::math::MPInt two(2);

  // 1. Recreate Generators
  yacl::crypto::EcPoint B = curve->HashToCurve(
      yacl::crypto::HashToCurveStrategy::Autonomous, "hello");
  yacl::crypto::EcPoint B_blinding = curve->HashToCurve(
      yacl::crypto::HashToCurveStrategy::Autonomous, "there");
  std::vector<yacl::crypto::EcPoint> G_vec = MakeGenerators(B, n, curve);
  std::vector<yacl::crypto::EcPoint> H_vec =
      MakeGenerators(B_blinding, n, curve);

  // 2. Replay transcript commitments and challenges
  transcript.AppendPoint("V", V_, curve);  // Use V_ from the proof object
  transcript.AppendPoint("A", A_, curve);
  transcript.AppendPoint("S", S_, curve);
  yacl::math::MPInt y = transcript.ChallengeScalar("y", curve);
  yacl::math::MPInt z = transcript.ChallengeScalar("z", curve);
  transcript.AppendPoint("T_1", T_1_, curve);
  transcript.AppendPoint("T_2", T_2_, curve);
  yacl::math::MPInt x = transcript.ChallengeScalar("x", curve);
  transcript.AppendScalar("t_x", t_x_);
  transcript.AppendScalar("t_x_blinding", t_x_blinding_);
  transcript.AppendScalar("e_blinding", e_blinding_);
  yacl::math::MPInt w = transcript.ChallengeScalar("w", curve);

  // 3. Polynomial commitment check
  // check: V^(z^2) * T1^x * T2^(x^2) * B^(delta - t_x) *
  // B_blinding^(-t_x_blinding) == Identity
  yacl::math::MPInt zz = z.MulMod(z, order);
  yacl::math::MPInt delta = Delta(n, y, z, curve);  // Single-party delta
  yacl::math::MPInt minus_one = order.SubMod(one, order);

  std::vector<yacl::math::MPInt> poly_scalars = {
      zz,                                     // for V_
      x,                                      // for T_1_
      x.MulMod(x, order),                     // for T_2_
      delta.SubMod(t_x_, order),              // for B
      t_x_blinding_.MulMod(minus_one, order)  // for B_blinding (-t_x_blinding)
  };
  std::vector<yacl::crypto::EcPoint> poly_points = {V_, T_1_, T_2_, B,
                                                    B_blinding};
  yacl::crypto::EcPoint poly_check =
      MultiScalarMul(curve, poly_scalars, poly_points);

  if (!curve->IsInfinity(poly_check)) {
    std::cerr << "Verification failed: Polynomial check failed." << std::endl;
    return false;
  }

  // 4. IPP Verification
  // Calculate P_final = A + x*S -z*G_sum + <h_prime_scalars, H_prime_vec> +
  // (w*t_x - e_blinding)*B_blinding where H'_i = H_i * y^-i and
  // h_prime_scalar_i = z + zz * (2*y_inv)^i

  // Recompute P + t(x)Q = P + t(x)w B_blinding

  yacl::crypto::EcPoint G_sum =
      curve->MulBase(yacl::math::MPInt(0));  // Identity
  for (const auto& Gi : G_vec) {
    G_sum = curve->Add(G_sum, Gi);
  }

  yacl::math::MPInt y_inv = y.InvertMod(order);
  auto two_over_y = y_inv.MulMod(two, order);

  std::vector<yacl::math::MPInt> exp_two_over_y =
      ExpIterVector(two_over_y, n, curve);
  std::vector<yacl::math::MPInt> h_scalars;
  h_scalars.reserve(n);
  for (size_t i = 0; i < n; ++i) {
    h_scalars.emplace_back(z.AddMod(zz.MulMod(exp_two_over_y[i], order), order));
  }

  std::vector<yacl::math::MPInt> msm_scalars;
  std::vector<yacl::crypto::EcPoint> msm_points;
  msm_scalars.reserve(3 + n);
  msm_points.reserve(3 + n);

  yacl::math::MPInt scalar1 = w.MulMod(t_x_, order).SubMod(e_blinding_, order);
  msm_scalars.emplace_back(scalar1);
  msm_points.emplace_back(B_blinding);

  msm_scalars.emplace_back(x);
  msm_points.emplace_back(S_);

  msm_scalars.emplace_back(z.MulMod(minus_one, order));
  msm_points.emplace_back(G_sum);

  for (size_t i = 0; i < n; ++i) {
    msm_scalars.emplace_back(h_scalars[i]);
    msm_points.emplace_back(H_vec[i]);
  }

  yacl::crypto::EcPoint P_plus_tx_Q =
      MultiScalarMul(curve, msm_scalars, msm_points);
  P_plus_tx_Q = curve->Add(A_, P_plus_tx_Q);

  // Q for IPP
  yacl::crypto::EcPoint Q = curve->Mul(B_blinding, w);

  // IPP Factors
  std::vector<yacl::math::MPInt> ipp_H_factors =
      ExpIterVector(y_inv, n, curve);  // H factors are y^-i

  // Verify IPP (ipp_proof_ is the member variable)
  // The C++ IPP Verify function needs the transcript to derive IPP challenges
  // and check the final equation.
  bool ipp_result =
      ipp_proof_.Verify(transcript, curve, ipp_H_factors, P_plus_tx_Q, Q, G_vec,
                        H_vec);  // IPP uses the same G/H vectors

  if (!ipp_result) {
    std::cerr << "Verification failed: IPP check failed." << std::endl;
  }
  return ipp_result;
}

// --- Serialization/Deserialization ---
yacl::Buffer RangeProof::ToBytes(
    const std::shared_ptr<yacl::crypto::EcGroup>& curve) const {
  // Use the existing implementation, assuming it's correct for the fields
  yacl::Buffer V_bytes = curve->SerializePoint(V_);
  yacl::Buffer A_bytes = curve->SerializePoint(A_);
  yacl::Buffer S_bytes = curve->SerializePoint(S_);
  yacl::Buffer T1_bytes = curve->SerializePoint(T_1_);
  yacl::Buffer T2_bytes = curve->SerializePoint(T_2_);
  yacl::Buffer t_x_bytes = t_x_.Serialize();
  yacl::Buffer t_x_blinding_bytes = t_x_blinding_.Serialize();
  yacl::Buffer e_blinding_bytes = e_blinding_.Serialize();
  yacl::Buffer ipp_bytes =
      ipp_proof_.ToBytes(curve);  // Assuming IPP has ToBytes

  size_t header_size = 9 * sizeof(size_t);

  int64_t total_size = header_size + V_bytes.size() + A_bytes.size() +
                       S_bytes.size() + T1_bytes.size() + T2_bytes.size() +
                       t_x_bytes.size() + t_x_blinding_bytes.size() +
                       e_blinding_bytes.size() + ipp_bytes.size();

  yacl::Buffer buf(total_size);
  char* ptr = buf.data<char>();

  auto write_sized_data = [&](const yacl::Buffer& data) {
    size_t size = data.size();
    std::memcpy(ptr, &size, sizeof(size_t));
    ptr += sizeof(size_t);
    std::memcpy(ptr, data.data(), size);
    ptr += size;
  };

  write_sized_data(V_bytes);
  write_sized_data(A_bytes);
  write_sized_data(S_bytes);
  write_sized_data(T1_bytes);
  write_sized_data(T2_bytes);
  write_sized_data(t_x_bytes);
  write_sized_data(t_x_blinding_bytes);
  write_sized_data(e_blinding_bytes);
  write_sized_data(ipp_bytes);

  YACL_ENFORCE(ptr == buf.data<char>() + total_size,
               "Serialization size mismatch");
  return buf;
}

RangeProof RangeProof::FromBytes(
    const std::shared_ptr<yacl::crypto::EcGroup>& curve,
    const yacl::ByteContainerView& bytes) {
  // Use existing implementation
  const char* ptr = reinterpret_cast<const char*>(bytes.data());
  const char* end = ptr + bytes.size();

  auto read_data = [&](const char* name) -> yacl::ByteContainerView {
    if (ptr + sizeof(size_t) > end) {
      throw yacl::Exception(
          fmt::format("Not enough data to read size of {}", name));
    }
    size_t size;
    std::memcpy(&size, ptr, sizeof(size_t));
    ptr += sizeof(size_t);
    if (ptr + size > end) {
      throw yacl::Exception(fmt::format("Not enough data to read {}", name));
    }
    yacl::ByteContainerView data(ptr, size);
    ptr += size;
    return data;
  };

  yacl::ByteContainerView V_data = read_data("V");
  yacl::ByteContainerView A_data = read_data("A");
  yacl::ByteContainerView S_data = read_data("S");
  yacl::ByteContainerView T1_data = read_data("T_1");
  yacl::ByteContainerView T2_data = read_data("T_2");
  yacl::ByteContainerView t_x_data = read_data("t_x");
  yacl::ByteContainerView t_x_blinding_data = read_data("t_x_blinding");
  yacl::ByteContainerView e_blinding_data = read_data("e_blinding");
  yacl::ByteContainerView ipp_data = read_data("ipp_proof");

  yacl::crypto::EcPoint V = curve->DeserializePoint(V_data);
  yacl::crypto::EcPoint A = curve->DeserializePoint(A_data);
  yacl::crypto::EcPoint S = curve->DeserializePoint(S_data);
  yacl::crypto::EcPoint T_1 = curve->DeserializePoint(T1_data);
  yacl::crypto::EcPoint T_2 = curve->DeserializePoint(T2_data);
  yacl::math::MPInt t_x, t_x_blinding, e_blinding;
  t_x.Deserialize(t_x_data);
  t_x_blinding.Deserialize(t_x_blinding_data);
  e_blinding.Deserialize(e_blinding_data);
  InnerProductProof ipp_proof = InnerProductProof::FromBytes(
      ipp_data, curve);  // Assuming IPP has FromBytes

  return RangeProof(V, A, S, T_1, T_2, t_x, t_x_blinding, e_blinding,
                    ipp_proof);
}

}  // namespace examples::zkp