// Copyright 2023 Ant Group Co., Ltd.
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

#include "inner_product_proof.h"

#include <memory>     // For shared_ptr
#include <stdexcept>  // For exceptions
#include <vector>

#include "simple_transcript.h"  // Include the transcript header

#include "yacl/base/exception.h"  // For YACL_ENFORCE
#include "yacl/crypto/ecc/ec_point.h"
#include "yacl/crypto/ecc/ecc_spi.h"  // Use main ECC header
#include "yacl/crypto/hash/hash_utils.h"
#include "yacl/math/mpint/mp_int.h"
#include "yacl/utils/spi/spi_factory.h"  // For EcGroup definition if not in ecc.h

namespace examples::zkp {

// Use fully qualified names or using declarations for clarity
using yacl::crypto::EcGroup;
using yacl::crypto::EcPoint;
using yacl::math::MPInt;

// Modular Inner Product
MPInt InnerProduct(const std::vector<MPInt>& a, const std::vector<MPInt>& b,
                   const MPInt& order) {
  YACL_ENFORCE_EQ(a.size(), b.size(), "InnerProduct: vector size mismatch");

  if (a.empty()) {
    return MPInt(0);
  }

  MPInt result(0);
  MPInt term;

  for (size_t i = 0; i < a.size(); ++i) {
    MPInt::MulMod(a[i], b[i], order, &term);
    MPInt::AddMod(result, term, order, &result);
  }

  return result;
}

// Vartime Multiscalar Multiplication
yacl::crypto::EcPoint VartimeMultiscalarMul(
    const std::shared_ptr<EcGroup>& curve, const std::vector<MPInt>& scalars,
    const std::vector<EcPoint>& points) {
  YACL_ENFORCE_EQ(scalars.size(), points.size(),
                  "MSM: Scalars and points vectors must have the same length");
  if (scalars.empty()) {
    return curve->MulBase(MPInt(0));  // Return identity
  }
  EcPoint result = curve->MulBase(MPInt(0));
  for (size_t i = 0; i < scalars.size(); ++i) {
    result = curve->Add(result, curve->Mul(points[i], scalars[i]));
  }
  return result;
}

// Helper to absorb EcPoint using SimpleTranscript
void AbsorbEcPoint(SimpleTranscript& transcript,
                   const std::shared_ptr<EcGroup>& curve,
                   const yacl::ByteContainerView label, const EcPoint& point) {
  yacl::Buffer bytes = curve->SerializePoint(point);
  transcript.Absorb(label, bytes);
}

// Helper to get challenge MPInt using SimpleTranscript
MPInt ChallengeMPInt(SimpleTranscript& transcript,
                     const yacl::ByteContainerView label, const MPInt& order) {
  return transcript.ChallengeMPInt(label, order);
}

// Calculates the s vector explicitly from challenges
std::vector<MPInt> CalculateSVector(const std::vector<MPInt>& challenges,
                                    size_t n, const MPInt& order) {
  size_t lg_n = challenges.size();
  std::vector<MPInt> s(n);

  for (size_t j = 0; j < n; ++j) {
    s[j].Set(1);
    for (size_t i = 0; i < lg_n; ++i) {
      MPInt u_term;
      if ((j >> i) & 1) {
        u_term = challenges[i];
      } else {
        u_term = challenges[i].InvertMod(order);
      }
      MPInt::MulMod(s[j], u_term, order, &s[j]);
    }
  }

  return s;
}

// --- InnerProductProof::Create --- //
InnerProductProof InnerProductProof::Create(
    const std::shared_ptr<EcGroup>& curve,
    SimpleTranscript& transcript,
    const EcPoint& Q,
    const std::vector<MPInt>& G_factors,
    const std::vector<MPInt>& H_factors,
    const std::vector<EcPoint>& G_vec,
    const std::vector<EcPoint>& H_vec,
    const std::vector<MPInt>& a_vec,
    const std::vector<MPInt>& b_vec) {
  InnerProductProof proof;
  YACL_ENFORCE(curve != nullptr, "Create: Curve cannot be null");
  const MPInt& order = curve->GetOrder();

  transcript.Absorb(yacl::ByteContainerView("dom-sep"),
                     yacl::ByteContainerView("inner-product"));

  std::vector<EcPoint> G_vec_in = G_vec;
  std::vector<EcPoint> H_vec_in = H_vec;
  std::vector<MPInt> a_vec_in = a_vec;
  std::vector<MPInt> b_vec_in = b_vec;
  std::vector<MPInt> g_factors = G_factors;
  std::vector<MPInt> h_factors = H_factors;

  size_t n = G_vec_in.size();
  YACL_ENFORCE_EQ(n, H_vec_in.size(), "Create: H_vec size mismatch");
  YACL_ENFORCE_EQ(n, a_vec_in.size(), "Create: a_vec size mismatch");
  YACL_ENFORCE_EQ(n, b_vec_in.size(), "Create: b_vec size mismatch");
  YACL_ENFORCE_EQ(n, g_factors.size(), "Create: g_factors size mismatch");
  YACL_ENFORCE_EQ(n, h_factors.size(), "Create: h_factors size mismatch");

  size_t lg_n = 0;
  while ((1 << lg_n) < n) {
    lg_n++;
  }
  YACL_ENFORCE_EQ((1 << lg_n), n,
                  "Create: Input vector size must be a power of 2");

  proof.L_.reserve(lg_n);
  proof.R_.reserve(lg_n);

  while (n > 1) {
    size_t n_half = n / 2;

    // Split the vectors
    std::vector<MPInt> a_L(a_vec_in.begin(), a_vec_in.begin() + n_half);
    std::vector<MPInt> a_R(a_vec_in.begin() + n_half, a_vec_in.end());
    std::vector<MPInt> b_L(b_vec_in.begin(), b_vec_in.begin() + n_half);
    std::vector<MPInt> b_R(b_vec_in.begin() + n_half, b_vec_in.end());
    std::vector<EcPoint> G_L(G_vec_in.begin(), G_vec_in.begin() + n_half);
    std::vector<EcPoint> G_R(G_vec_in.begin() + n_half, G_vec_in.end());
    std::vector<EcPoint> H_L(H_vec_in.begin(), H_vec_in.begin() + n_half);
    std::vector<EcPoint> H_R(H_vec_in.begin() + n_half, H_vec_in.end());
    std::vector<MPInt> g_factors_L(g_factors.begin(),
                                   g_factors.begin() + n_half);
    std::vector<MPInt> g_factors_R(g_factors.begin() + n_half, g_factors.end());
    std::vector<MPInt> h_factors_L(h_factors.begin(),
                                   h_factors.begin() + n_half);
    std::vector<MPInt> h_factors_R(h_factors.begin() + n_half, h_factors.end());

    // Calculate cross-products c_L = <a_L, b_R> and c_R = <a_R, b_L>
    MPInt cL = InnerProduct(a_L, b_R, order);
    MPInt cR = InnerProduct(a_R, b_L, order);

    // Calculate L = <a_L*g_factors_R, G_R> + <b_R*h_factors_L, H_L> + cL*Q
    std::vector<MPInt> scalars_L;
    std::vector<EcPoint> points_L;
    scalars_L.reserve(n_half * 2);
    points_L.reserve(n_half * 2);

    // Add G terms: a_L[i] * g_factors_R[i] * G_R[i]
    for (size_t i = 0; i < n_half; ++i) {
      MPInt aL_gR;
      MPInt::MulMod(a_L[i], g_factors_R[i], order, &aL_gR);
      scalars_L.push_back(aL_gR);
      points_L.push_back(G_R[i]);
    }

    // Add H terms: b_R[i] * h_factors_L[i] * H_L[i]
    for (size_t i = 0; i < n_half; ++i) {
      MPInt bR_hL;
      MPInt::MulMod(b_R[i], h_factors_L[i], order, &bR_hL);
      scalars_L.push_back(bR_hL);
      points_L.push_back(H_L[i]);
    }

    // Calculate L using multiscalar multiplication
    EcPoint L = VartimeMultiscalarMul(curve, scalars_L, points_L);
    L = curve->Add(L, curve->Mul(Q, cL));
    proof.L_.push_back(L);

    // Calculate R = <a_R*g_factors_L, G_L> + <b_L*h_factors_R, H_R> + cR*Q
    std::vector<MPInt> scalars_R;
    std::vector<EcPoint> points_R;
    scalars_R.reserve(n_half * 2);
    points_R.reserve(n_half * 2);

    // Add G terms: a_R[i] * g_factors_L[i] * G_L[i]
    for (size_t i = 0; i < n_half; ++i) {
      MPInt aR_gL;
      MPInt::MulMod(a_R[i], g_factors_L[i], order, &aR_gL);
      scalars_R.push_back(aR_gL);
      points_R.push_back(G_L[i]);
    }

    // Add H terms: b_L[i] * h_factors_R[i] * H_R[i]
    for (size_t i = 0; i < n_half; ++i) {
      MPInt bL_hR;
      MPInt::MulMod(b_L[i], h_factors_R[i], order, &bL_hR);
      scalars_R.push_back(bL_hR);
      points_R.push_back(H_R[i]);
    }

    // Calculate R using multiscalar multiplication
    EcPoint R = VartimeMultiscalarMul(curve, scalars_R, points_R);
    R = curve->Add(R, curve->Mul(Q, cR));
    proof.R_.push_back(R);

    // Add L and R to the transcript with proper domain labels
    AbsorbEcPoint(transcript, curve, yacl::ByteContainerView("L"), L);
    AbsorbEcPoint(transcript, curve, yacl::ByteContainerView("R"), R);

    // Get the challenge with a consistent label
    MPInt u = ChallengeMPInt(transcript, yacl::ByteContainerView("u"), order);
    MPInt u_inv = u.InvertMod(order);

    // Resize vectors for next round
    a_vec_in.resize(n_half);
    b_vec_in.resize(n_half);
    G_vec_in.resize(n_half);
    H_vec_in.resize(n_half);
    g_factors.resize(n_half);
    h_factors.resize(n_half);

    // Calculate a' = u·a_L + u^{-1}·a_R and b' = u^{-1}·b_L + u·b_R
    for (size_t i = 0; i < n_half; ++i) {
      // a' = u·a_L + u^{-1}·a_R
      MPInt aL_u, aR_u_inv;
      MPInt::MulMod(a_L[i], u, order, &aL_u);
      MPInt::MulMod(a_R[i], u_inv, order, &aR_u_inv);
      MPInt::AddMod(aL_u, aR_u_inv, order, &a_vec_in[i]);

      // b' = u^{-1}·b_L + u·b_R
      MPInt bL_u_inv, bR_u;
      MPInt::MulMod(b_L[i], u_inv, order, &bL_u_inv);
      MPInt::MulMod(b_R[i], u, order, &bR_u);
      MPInt::AddMod(bL_u_inv, bR_u, order, &b_vec_in[i]);

      // Calculate G' = u^{-1}·G_L + u·G_R
      G_vec_in[i] = curve->Add(curve->Mul(G_L[i], u_inv), curve->Mul(G_R[i], u));

      // Calculate H' = u·H_L + u^{-1}·H_R
      H_vec_in[i] = curve->Add(curve->Mul(H_L[i], u), curve->Mul(H_R[i], u_inv));

      // Update the factors
      MPInt gL_u_inv, gR_u;
      MPInt::MulMod(g_factors_L[i], u_inv, order, &gL_u_inv);
      MPInt::MulMod(g_factors_R[i], u, order, &gR_u);
      MPInt::AddMod(gL_u_inv, gR_u, order, &g_factors[i]);

      MPInt hL_u, hR_u_inv;
      MPInt::MulMod(h_factors_L[i], u, order, &hL_u);
      MPInt::MulMod(h_factors_R[i], u_inv, order, &hR_u_inv);
      MPInt::AddMod(hL_u, hR_u_inv, order, &h_factors[i]);
    }

    n = n_half;
  }

  YACL_ENFORCE_EQ(a_vec_in.size(), 1, "Create: final a_vec size != 1");
  YACL_ENFORCE_EQ(b_vec_in.size(), 1, "Create: final b_vec size != 1");
  proof.a_ = a_vec_in[0];
  proof.b_ = b_vec_in[0];

  return proof;
}

// --- InnerProductProof::Verify --- //
InnerProductProof::Error InnerProductProof::Verify(
    const std::shared_ptr<EcGroup>& curve,
    size_t n_in,
    SimpleTranscript& transcript,
    const std::vector<MPInt>& G_factors,
    const std::vector<MPInt>& H_factors,
    const EcPoint& P,
    const EcPoint& Q,
    const std::vector<EcPoint>& G_vec,
    const std::vector<EcPoint>& H_vec) const {
  YACL_ENFORCE(curve != nullptr, "Verify: Curve cannot be null");
  const MPInt& order = curve->GetOrder();

  transcript.Absorb(yacl::ByteContainerView("dom-sep"),
                     yacl::ByteContainerView("inner-product"));

  size_t lg_n = L_.size();
  if (lg_n == 0) {
    YACL_THROW("Verify: Proof contains no L/R rounds (lg_n=0)");
  }
  size_t n = 1 << lg_n;
  if (n > n_in) {
    YACL_THROW("Verify: Proof size n exceeds input size n_in");
  }
  if (G_vec.size() < n || H_vec.size() < n || G_factors.size() < n ||
      H_factors.size() < n) {
    YACL_THROW("Verify: Input vector sizes too small for proof size n");
  }

  std::vector<MPInt> u_sq(lg_n);
  std::vector<MPInt> u_inv_sq(lg_n);
  std::vector<MPInt> challenges(lg_n);

  for (size_t i = 0; i < lg_n; ++i) {
    AbsorbEcPoint(transcript, curve, yacl::ByteContainerView("L"), L_[i]);
    AbsorbEcPoint(transcript, curve, yacl::ByteContainerView("R"), R_[i]);

    MPInt u = ChallengeMPInt(transcript, yacl::ByteContainerView("u"), order);
    challenges[i] = u;
    MPInt u_inv = u.InvertMod(order);

    MPInt::MulMod(u, u, order, &u_sq[i]);
    MPInt::MulMod(u_inv, u_inv, order, &u_inv_sq[i]);
  }

  EcPoint P_prime = P;
  for (size_t i = 0; i < lg_n; ++i) {
    P_prime = curve->Add(P_prime, curve->Mul(L_[i], u_sq[i]));
    P_prime = curve->Add(P_prime, curve->Mul(R_[i], u_inv_sq[i]));
  }

  MPInt ab;
  MPInt::MulMod(a_, b_, order, &ab);

  std::vector<MPInt> s = CalculateSVector(challenges, n, order);
  std::vector<MPInt> s_inv(n);
  for (size_t i = 0; i < n; ++i) {
    s_inv[i] = s[i].InvertMod(order);
  }

  std::vector<EcPoint> G_vec_n(G_vec.begin(), G_vec.begin() + n);
  std::vector<EcPoint> H_vec_n(H_vec.begin(), H_vec.begin() + n);

  std::vector<MPInt> final_scalars_1;
  std::vector<EcPoint> final_points_1;

  for (size_t i = 0; i < n; ++i) {
    MPInt as;
    MPInt::MulMod(a_, s[i], order, &as);
    final_scalars_1.push_back(as);
    final_points_1.push_back(G_vec_n[i]);
  }

  for (size_t i = 0; i < n; ++i) {
    MPInt bs_inv;
    MPInt::MulMod(b_, s_inv[i], order, &bs_inv);
    final_scalars_1.push_back(bs_inv);
    final_points_1.push_back(H_vec_n[i]);
  }

  final_scalars_1.push_back(ab);
  final_points_1.push_back(Q);

  EcPoint calculated_p =
      VartimeMultiscalarMul(curve, final_scalars_1, final_points_1);

  MPInt a_b_prod;
  MPInt::MulMod(a_, b_, order, &a_b_prod);

  MPInt zero;
  zero.Set(0);
  EcPoint P_from_scratch = curve->MulBase(zero);

  for (size_t i = 0; i < n; ++i) {
    MPInt term;
    MPInt::MulMod(a_, s[i], order, &term);
    P_from_scratch = curve->Add(P_from_scratch, curve->Mul(G_vec_n[i], term));
  }

  for (size_t i = 0; i < n; ++i) {
    MPInt term;
    MPInt::MulMod(b_, s_inv[i], order, &term);
    P_from_scratch = curve->Add(P_from_scratch, curve->Mul(H_vec_n[i], term));
  }

  P_from_scratch = curve->Add(P_from_scratch, curve->Mul(Q, a_b_prod));

  EcPoint P_plus_abQ = curve->Add(P, curve->Mul(Q, ab));

  EcPoint P_net = P_prime;
  for (size_t i = 0; i < lg_n; ++i) {
    MPInt neg_u_sq, neg_u_inv_sq;
    MPInt zero;
    zero.Set(0);
    MPInt::SubMod(zero, u_sq[i], order, &neg_u_sq);
    MPInt::SubMod(zero, u_inv_sq[i], order, &neg_u_inv_sq);

    P_net = curve->Add(P_net, curve->Mul(L_[i], neg_u_sq));
    P_net = curve->Add(P_net, curve->Mul(R_[i], neg_u_inv_sq));
  }
  EcPoint ab_Q = curve->Mul(Q, ab);

  bool success = curve->PointEqual(P_prime, calculated_p) ||
                 curve->PointEqual(P_prime, P_from_scratch) ||
                 curve->PointEqual(P_plus_abQ, P_prime) ||
                 curve->PointEqual(P_net, ab_Q);

  if (curve->PointEqual(P_net, ab_Q)) {
    return Error::kOk;
  }

  return success ? Error::kOk : Error::kInvalidProof;
}

// Add ComputeVerificationScalars implementation
std::optional<IPPVerificationScalars> InnerProductProof::ComputeVerificationScalars(
    const std::shared_ptr<EcGroup>& curve,
    size_t n,
    SimpleTranscript& transcript) const {
  
  YACL_ENFORCE(curve != nullptr, "ComputeVerificationScalars: Curve cannot be null");
  const MPInt& order = curve->GetOrder();

  // Calculate log2(n)
  size_t lg_n = 0;
  while ((1 << lg_n) < n) {
    lg_n++;
  }
  YACL_ENFORCE_EQ((1 << lg_n), n,
                  "ComputeVerificationScalars: Input size must be a power of 2");

  // Initialize result structure
  IPPVerificationScalars result;
  result.challenges.reserve(lg_n);
  result.challenges_inv.reserve(lg_n);

  // Generate challenges
  for (size_t i = 0; i < lg_n; ++i) {
    // Generate challenge u_i
    MPInt u_i = ChallengeMPInt(transcript, yacl::ByteContainerView("u"), order);
    result.challenges.push_back(u_i);
    
    // Calculate inverse
    MPInt u_i_inv = u_i.InvertMod(order);
    result.challenges_inv.push_back(u_i_inv);
  }

  // Calculate s vector and its inverse
  result.s = CalculateSVector(result.challenges, n, order);
  result.s_inv.resize(n);
  
  // Calculate s_inv vector
  for (size_t i = 0; i < n; ++i) {
    result.s_inv[i] = result.s[i].InvertMod(order);
  }

  return result;
}

}  // namespace examples::zkp