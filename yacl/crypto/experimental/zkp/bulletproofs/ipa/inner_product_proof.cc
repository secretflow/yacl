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

#include "yacl/crypto/experimental/zkp/bulletproofs/ipa/inner_product_proof.h"

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstring>
#include <stdexcept>

#include "yacl/crypto/experimental/zkp/bulletproofs/util.h"  // For exponentiation helpers
#include "yacl/crypto/experimental/zkp/bulletproofs/errors.h"

namespace examples::zkp {

InnerProductProof InnerProductProof::Create(
    SimpleTranscript& transcript,
    const std::shared_ptr<yacl::crypto::EcGroup>& curve,
    const yacl::crypto::EcPoint& Q,
    const std::vector<yacl::math::MPInt>& H_factors,
    std::vector<yacl::crypto::EcPoint> G_vec,  // Pass by value
    std::vector<yacl::crypto::EcPoint> H_vec,  // Pass by value
    std::vector<yacl::math::MPInt> a_vec,      // Pass by value
    std::vector<yacl::math::MPInt> b_vec) {    // Pass by value

  size_t n = G_vec.size();
  const auto& order = curve->GetOrder();

  // Validation
  YACL_ENFORCE(n > 0 && (n & (n - 1)) == 0, "n must be a power of 2 and > 0");
  YACL_ENFORCE(H_vec.size() == n && a_vec.size() == n && b_vec.size() == n &&
               H_factors.size() == n,
               "Vector size mismatch");

  // Apply H_factors to H_vec initially - Modify H_vec in place
  for (size_t i = 0; i < n; ++i) {
    H_vec[i] = curve->Mul(H_vec[i], H_factors[i]);
  }

  // Determine number of rounds
  size_t lg_n = FloorLog2(n);
  std::vector<yacl::crypto::EcPoint> L_vec_out;
  L_vec_out.reserve(lg_n);
  std::vector<yacl::crypto::EcPoint> R_vec_out;
  R_vec_out.reserve(lg_n);

  while (n > 1) {
    n = n / 2;

    // Create temporary vectors for calculations based on current range [lo, lo
    // + current_n) Scalars
    std::vector<yacl::math::MPInt> a_L(a_vec.begin(), a_vec.begin() + n);
    std::vector<yacl::math::MPInt> a_R(a_vec.begin() + n,
                                       a_vec.begin() + 2 * n);
    std::vector<yacl::math::MPInt> b_L(b_vec.begin(), b_vec.begin() + n);
    std::vector<yacl::math::MPInt> b_R(b_vec.begin() + n,
                                       b_vec.begin() + 2 * n);
    // Points
    std::vector<yacl::crypto::EcPoint> G_L(G_vec.begin(), G_vec.begin() + n);
    std::vector<yacl::crypto::EcPoint> G_R(G_vec.begin() + n,
                                           G_vec.begin() + 2 * n);
    std::vector<yacl::crypto::EcPoint> H_L(H_vec.begin(), H_vec.begin() + n);
    std::vector<yacl::crypto::EcPoint> H_R(H_vec.begin() + n,
                                           H_vec.begin() + 2 * n);

    // Compute c_L and c_R
    yacl::math::MPInt c_L = InnerProduct(a_L, b_R, curve);
    yacl::math::MPInt c_R = InnerProduct(a_R, b_L, curve);

    // Compute L = <a_L, G_R * G_fact_R> + <b_R, H_L> + c_L * Q
    std::vector<yacl::math::MPInt> L_scalars;
    L_scalars.reserve(n + n + 1);
    std::vector<yacl::crypto::EcPoint> L_points;
    L_points.reserve(n + n + 1);
    for (size_t i = 0; i < n; ++i) {
      L_scalars.emplace_back(a_L[i]);
      L_points.emplace_back(G_R[i]);
    }
    for (size_t i = 0; i < n; ++i) {
      L_scalars.emplace_back(b_R[i]);
      L_points.emplace_back(H_L[i]);
    }
    L_scalars.emplace_back(c_L);
    L_points.emplace_back(Q);
    yacl::crypto::EcPoint L = MultiScalarMul(curve, L_scalars, L_points);
    L_vec_out.emplace_back(L);

    // Compute R = <a_R, G_L> + <b_L, H_R> + c_R * Q
    std::vector<yacl::math::MPInt> R_scalars;
    R_scalars.reserve(n + n + 1);
    std::vector<yacl::crypto::EcPoint> R_points;
    R_points.reserve(n + n + 1);
    for (size_t i = 0; i < n; ++i) {
      R_scalars.emplace_back(a_R[i]);
      R_points.emplace_back(G_L[i]);
    }
    for (size_t i = 0; i < n; ++i) {
      R_scalars.emplace_back(b_L[i]);
      R_points.emplace_back(H_R[i]);
    }
    R_scalars.emplace_back(c_R);
    R_points.emplace_back(Q);
    yacl::crypto::EcPoint R = MultiScalarMul(curve, R_scalars, R_points);
    R_vec_out.emplace_back(R);

    // Get challenge x
    // TODO: Check if AppendPoint needs compressed format
    transcript.AppendPoint("L", L, curve);
    transcript.AppendPoint("R", R, curve);
    yacl::math::MPInt x = transcript.ChallengeScalar("u", curve);  //
    yacl::math::MPInt x_inv = x.InvertMod(order);

    // Update vectors for next round (modify originals in the range [lo, mid))
    for (size_t i = 0; i < n; ++i) {
      // a = a_L * x + a_R * x_inv
      a_L[i] =
          a_L[i].MulMod(x, order).AddMod(a_R[i].MulMod(x_inv, order), order);
      // b = b_L * x_inv + b_R * x
      b_L[i] =
          b_L[i].MulMod(x_inv, order).AddMod(b_R[i].MulMod(x, order), order);
      // G = G_L * x_inv + G_R * x <- Careful with
      // factors G_new = G_L*x_inv + G_R*x (This matches  if factors are 1)
      // Let's compute the updated points without factors here, assuming factors
      // are applied outside/in verify
      G_L[i] = MultiScalarMul(curve, {x_inv, x}, {G_L[i], G_R[i]});
      // H = H_L * x + H_R * x_inv (H already includes H_factors)
      H_L[i] = MultiScalarMul(curve, {x, x_inv}, {H_L[i], H_R[i]});
    }

    a_vec = a_L;
    b_vec = b_L;
    G_vec = G_L;
    H_vec = H_L;
  }

  // Return final proof
  return InnerProductProof(L_vec_out, R_vec_out, a_vec[0], b_vec[0]);
}

std::tuple<std::vector<yacl::math::MPInt>, std::vector<yacl::math::MPInt>,
           std::vector<yacl::math::MPInt>>
InnerProductProof::VerificationScalars(
    size_t n,  // The original vector length (vector size = n)
    SimpleTranscript& transcript,
    const std::shared_ptr<yacl::crypto::EcGroup>& curve) const {
  size_t lg_n = L_vec_.size();  // Number of rounds = log2(n)

#if SPDLOG_INFO
  std::cout << "\n--- InnerProductProof::VerificationScalars Start (n=" << n
            << ", lg_n=" << lg_n << ") ---" << std::endl;
#endif

  // --- Basic Checks ---
  YACL_ENFORCE(lg_n < 32, "Inner product proof too large (lg_n >= 32)");
  YACL_ENFORCE(n > 0 && (n == (1ULL << lg_n)),
               "Input n must be 2^lg_n and positive");  // Check n is power of 2
                                                        // and matches lg_n
  YACL_ENFORCE(R_vec_.size() == lg_n, "L_vec and R_vec size mismatch");

  transcript.InnerproductDomainSep(n);

  // --- 1. Recompute challenges u_i from transcript ---
  std::vector<yacl::math::MPInt> challenges(lg_n);
  std::vector<yacl::math::MPInt> challenges_inv(lg_n);  // Store inverses too

#if SPDLOG_INFO
  std::cout << "Recomputing challenges..." << std::endl;
#endif
  for (size_t i = 0; i < lg_n; ++i) {
    // Append points in the same order as prover
    transcript.AppendPoint("L", L_vec_[i], curve);
    transcript.AppendPoint("R", R_vec_[i], curve);
    // Recompute challenge for this round
    challenges[i] = transcript.ChallengeScalar("u", curve);
    challenges_inv[i] =
        challenges[i].InvertMod(curve->GetOrder());  // Compute inverse now
#if SPDLOG_INFO
    std::cout << "  u_" << (i + 1) << " = " << challenges[i] << ", u_inv_"
              << (i + 1) << " = " << challenges_inv[i] << std::endl;
#endif
  }

  // --- 2. Compute squares of challenges and inverses ---
  std::vector<yacl::math::MPInt> challenges_sq(lg_n);
  std::vector<yacl::math::MPInt> challenges_inv_sq(lg_n);
  for (size_t i = 0; i < lg_n; ++i) {
    challenges_sq[i] = challenges[i].MulMod(challenges[i], curve->GetOrder());
    challenges_inv_sq[i] =
        challenges_inv[i].MulMod(challenges_inv[i], curve->GetOrder());
  }

  // --- 3. Compute s vector ---
  std::vector<yacl::math::MPInt> s(n);
  // Compute s[0] = product_{j=0}^{lg_n-1} u_{j+1}^{-1}
  yacl::math::MPInt s_0(1);
  for (const auto& inv : challenges_inv) {
    s_0 = s_0.MulMod(inv, curve->GetOrder());
  }
  s[0] = s_0;

#if SPDLOG_INFO
  std::cout << "Computing s vector (size " << n << ")..." << std::endl;
  std::cout << "  s[0] = " << s[0] << std::endl;
#endif

  for (size_t i = 1; i < n; ++i) {
    // Find the 0-based index of the highest set bit of i
    size_t lg_i = FloorLog2(i);
    size_t k = 1ULL << lg_i;  // k = 2^{lg_i}

    // The challenges are stored in "creation order" as [u_1, u_2,..., u_lg_n]
    // challenges_sq holds [u_1^2, u_2^2, ..., u_lg_n^2]
    //  code uses index (lg_n - 1) - lg_i
    size_t challenge_idx = (lg_n - 1) - lg_i;
    YACL_ENFORCE(challenge_idx < challenges_sq.size(),
                 "Logic error: challenge_idx out of bounds");
    const yacl::math::MPInt& u_sq_for_level = challenges_sq[challenge_idx];

    // Find the previous index `i - k`
    size_t prev_i = i - k;
    YACL_ENFORCE(prev_i < i, "Logic error: prev_i >= i");

    // Calculate s[i] = s[prev_i] * u_sq_for_level
    s.at(i) = s.at(prev_i).MulMod(u_sq_for_level, curve->GetOrder());

#if SPDLOG_INFO >= 2  // Only print s vector for higher debug levels
    // Correct the debug print to show the challenge index used
    std::cout << "  s[" << i << "] = s[" << prev_i << "] * challenges_sq["
              << challenge_idx << "] = " << s[i] << std::endl;
#endif
  }

#if SPDLOG_INFO
  std::cout << "--- InnerProductProof::VerificationScalars End ---"
            << std::endl;
#endif

  return {challenges_sq, challenges_inv_sq, s};
}

bool InnerProductProof::Verify(
    SimpleTranscript& transcript,
    const std::shared_ptr<yacl::crypto::EcGroup>& curve,
    const std::vector<yacl::math::MPInt>& H_factors,
    const yacl::crypto::EcPoint& P, const yacl::crypto::EcPoint& Q,
    const std::vector<yacl::crypto::EcPoint>& G,
    const std::vector<yacl::crypto::EcPoint>& H) const {
  std::cout << "InnerProductProof::Verify" << std::endl;

  try {
    size_t lg_n = L_vec_.size();
    size_t n = 1ULL << lg_n;
    auto order = curve->GetOrder();
    std::cout << "Verifying proof with n=" << n << ", lg_n=" << lg_n
              << std::endl;

    // --- 1. Recompute challenges u_i from transcript ---
    std::vector<yacl::math::MPInt> challenges;
    challenges.reserve(lg_n);
    for (size_t i = 0; i < lg_n; ++i) {
      transcript.AppendPoint("L", L_vec_[i], curve);
      transcript.AppendPoint("R", R_vec_[i], curve);
      challenges.emplace_back(transcript.ChallengeScalar("u", curve));
    }

    auto inv_challenges = challenges;
    yacl::math::MPInt allinv(1);
    for (size_t i = 0; i < lg_n; ++i) {
      inv_challenges[i] = inv_challenges[i].InvertMod(order);
      allinv = allinv.MulMod(inv_challenges[i], order);
    }

    auto challenges_sq = challenges;
    for (size_t i = 0; i < lg_n; ++i) {
      challenges_sq[i] = challenges_sq[i].MulMod(challenges_sq[i], order);
    }

    // --- 3. Compute s vector ---
    std::vector<yacl::math::MPInt> s(n);
    for (size_t i = 0; i < n; ++i) {
      auto s_i = allinv;
      for (size_t j = 0; j < lg_n; ++j) {
        if (1ULL & (i >> j)) {
          s_i = s_i.MulMod(challenges_sq[lg_n - 1 - j], order);
        }
      }
      s[i] = s_i;
    }

    std::vector<yacl::math::MPInt> a_times_s(n);
    for (size_t i = 0; i < n; ++i) {
      a_times_s[i] = a_.MulMod(s[i], order);
    }

    // 1/s[i] is s[!i], and !i runs from n-1 to 0 as i runs from 0 to n-1
    auto inv_s = s;
    std::reverse(inv_s.begin(), inv_s.end());

    std::vector<yacl::math::MPInt> h_times_b_div_s(n);
    for (size_t i = 0; i < n; ++i) {
      h_times_b_div_s[i] =
          H_factors[i].MulMod(b_, order).MulMod(inv_s[i], order);
    }

    std::vector<yacl::math::MPInt> neg_x_sq = challenges_sq;
    for (size_t i = 0; i < lg_n; ++i) {
      neg_x_sq[i] = neg_x_sq[i].MulMod(yacl::math::MPInt(-1), order);
    }

    std::vector<yacl::math::MPInt> neg_x_inv_sq = inv_challenges;
    for (size_t i = 0; i < lg_n; ++i) {
      neg_x_inv_sq[i] = neg_x_inv_sq[i]
                            .MulMod(neg_x_inv_sq[i], order)
                            .MulMod(yacl::math::MPInt(-1), order);
    }

    std::vector<yacl::math::MPInt> msm_scalars;
    msm_scalars.emplace_back(a_.MulMod(b_, order));
    msm_scalars.insert(msm_scalars.end(), a_times_s.begin(), a_times_s.end());
    msm_scalars.insert(msm_scalars.end(), h_times_b_div_s.begin(),
                       h_times_b_div_s.end());
    msm_scalars.insert(msm_scalars.end(), neg_x_sq.begin(), neg_x_sq.end());
    msm_scalars.insert(msm_scalars.end(), neg_x_inv_sq.begin(),
                       neg_x_inv_sq.end());

    std::vector<yacl::crypto::EcPoint> msm_points;
    msm_points.emplace_back(Q);
    msm_points.insert(msm_points.end(), G.begin(), G.end());
    msm_points.insert(msm_points.end(), H.begin(), H.end());
    msm_points.insert(msm_points.end(), L_vec_.begin(), L_vec_.end());
    msm_points.insert(msm_points.end(), R_vec_.begin(), R_vec_.end());

    auto expect_P = MultiScalarMul(curve, msm_scalars, msm_points);
    if (curve->PointEqual(expect_P, P)) {
      std::cout << "P match" << std::endl;
      return true;
    } else {
      std::cout << "P mismatch" << std::endl;
      return false;
    }
  } catch (const ProofError& e) {
    std::cout << "Caught ProofError (Type " << static_cast<int>(e.GetType()) << "): " << e.what() << std::endl;
    return false;
  }
}

yacl::Buffer InnerProductProof::ToBytes(
    const std::shared_ptr<yacl::crypto::EcGroup>& curve) const {
  yacl::Buffer bytes;

  // First, write the number of L/R pairs (needed for deserialization)
  uint32_t lg_n = static_cast<uint32_t>(L_vec_.size());
  bytes.resize(sizeof(lg_n));
  std::memcpy(bytes.data<uint8_t>(), &lg_n, sizeof(lg_n));

  // Serialize L and R vectors with size prefixes for each point
  for (size_t i = 0; i < L_vec_.size(); i++) {
    // L point
    yacl::Buffer L_bytes = curve->SerializePoint(L_vec_[i]);
    uint32_t L_size = static_cast<uint32_t>(L_bytes.size());

    size_t prev_size = bytes.size();
    bytes.resize(prev_size + sizeof(L_size) + L_size);
    std::memcpy(bytes.data<uint8_t>() + prev_size, &L_size, sizeof(L_size));
    std::memcpy(bytes.data<uint8_t>() + prev_size + sizeof(L_size),
                L_bytes.data<uint8_t>(), L_size);

    // R point
    yacl::Buffer R_bytes = curve->SerializePoint(R_vec_[i]);
    uint32_t R_size = static_cast<uint32_t>(R_bytes.size());

    prev_size = bytes.size();
    bytes.resize(prev_size + sizeof(R_size) + R_size);
    std::memcpy(bytes.data<uint8_t>() + prev_size, &R_size, sizeof(R_size));
    std::memcpy(bytes.data<uint8_t>() + prev_size + sizeof(R_size),
                R_bytes.data<uint8_t>(), R_size);
  }

  // Serialize a and b with size prefixes
  yacl::Buffer a_bytes = a_.Serialize();
  uint32_t a_size = static_cast<uint32_t>(a_bytes.size());

  size_t prev_size = bytes.size();
  bytes.resize(prev_size + sizeof(a_size) + a_size);
  std::memcpy(bytes.data<uint8_t>() + prev_size, &a_size, sizeof(a_size));
  std::memcpy(bytes.data<uint8_t>() + prev_size + sizeof(a_size),
              a_bytes.data<uint8_t>(), a_size);

  yacl::Buffer b_bytes = b_.Serialize();
  uint32_t b_size = static_cast<uint32_t>(b_bytes.size());

  prev_size = bytes.size();
  bytes.resize(prev_size + sizeof(b_size) + b_size);
  std::memcpy(bytes.data<uint8_t>() + prev_size, &b_size, sizeof(b_size));
  std::memcpy(bytes.data<uint8_t>() + prev_size + sizeof(b_size),
              b_bytes.data<uint8_t>(), b_size);

  return bytes;
}

InnerProductProof InnerProductProof::FromBytes(
    const yacl::ByteContainerView& bytes,
    const std::shared_ptr<yacl::crypto::EcGroup>& curve) {
  if (bytes.size() < sizeof(uint32_t)) {
    throw yacl::Exception("Invalid proof format: too short");
  }

  // Read the number of L/R pairs
  uint32_t lg_n;
  std::memcpy(&lg_n, bytes.data(), sizeof(lg_n));

  if (lg_n >= 32) {
    throw yacl::Exception("Proof too large");
  }

  std::vector<yacl::crypto::EcPoint> L_vec;
  std::vector<yacl::crypto::EcPoint> R_vec;
  L_vec.reserve(lg_n);
  R_vec.reserve(lg_n);

  size_t pos = sizeof(lg_n);

  // Read L and R points
  for (uint32_t i = 0; i < lg_n; i++) {
    // Check if there's enough data for size prefixes
    if (pos + sizeof(uint32_t) > bytes.size()) {
      throw yacl::Exception("Invalid proof format: truncated data");
    }

    // Read L point
    uint32_t L_size;
    std::memcpy(&L_size, bytes.data() + pos, sizeof(L_size));
    pos += sizeof(L_size);

    if (pos + L_size > bytes.size()) {
      throw yacl::Exception("Invalid proof format: truncated point data");
    }

    L_vec.emplace_back(curve->DeserializePoint(
        yacl::ByteContainerView(bytes.data() + pos, L_size)));
    pos += L_size;

    // Read R point
    if (pos + sizeof(uint32_t) > bytes.size()) {
      throw yacl::Exception("Invalid proof format: truncated data");
    }

    uint32_t R_size;
    std::memcpy(&R_size, bytes.data() + pos, sizeof(R_size));
    pos += sizeof(R_size);

    if (pos + R_size > bytes.size()) {
      throw yacl::Exception("Invalid proof format: truncated point data");
    }

    R_vec.emplace_back(curve->DeserializePoint(
        yacl::ByteContainerView(bytes.data() + pos, R_size)));
    pos += R_size;
  }

  // Read a and b scalars
  if (pos + sizeof(uint32_t) > bytes.size()) {
    throw yacl::Exception("Invalid proof format: truncated data");
  }

  uint32_t a_size;
  std::memcpy(&a_size, bytes.data() + pos, sizeof(a_size));
  pos += sizeof(a_size);

  if (pos + a_size > bytes.size()) {
    throw yacl::Exception("Invalid proof format: truncated scalar data");
  }

  yacl::math::MPInt a;
  a.FromMagBytes(yacl::ByteContainerView(bytes.data() + pos, a_size));
  pos += a_size;

  if (pos + sizeof(uint32_t) > bytes.size()) {
    throw yacl::Exception("Invalid proof format: truncated data");
  }

  uint32_t b_size;
  std::memcpy(&b_size, bytes.data() + pos, sizeof(b_size));
  pos += sizeof(b_size);

  if (pos + b_size > bytes.size()) {
    throw yacl::Exception("Invalid proof format: truncated scalar data");
  }

  yacl::math::MPInt b;
  b.FromMagBytes(yacl::ByteContainerView(bytes.data() + pos, b_size));

  // Make sure a and b are in the correct range
  a = a.Mod(curve->GetOrder());
  b = b.Mod(curve->GetOrder());

  return InnerProductProof(L_vec, R_vec, a, b);
}

}  // namespace examples::zkp