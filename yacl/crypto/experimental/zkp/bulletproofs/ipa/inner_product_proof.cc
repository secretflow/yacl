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

#include "yacl/crypto/experimental/zkp/bulletproofs/errors.h"
#include "yacl/crypto/experimental/zkp/bulletproofs/util.h"

namespace examples::zkp {

InnerProductProof InnerProductProof::Create(
    SimpleTranscript& transcript,
    const std::shared_ptr<yacl::crypto::EcGroup>& curve,
    const yacl::crypto::EcPoint& Q,
    const std::vector<yacl::math::MPInt>& G_factors,
    const std::vector<yacl::math::MPInt>& H_factors,
    std::vector<yacl::crypto::EcPoint> G_vec,
    std::vector<yacl::crypto::EcPoint> H_vec,
    std::vector<yacl::math::MPInt> a_vec,
    std::vector<yacl::math::MPInt> b_vec) {
  size_t original_n = G_vec.size();
  const auto& order = curve->GetOrder();

  YACL_ENFORCE(original_n > 0 && (original_n & (original_n - 1)) == 0,
               "n must be a power of 2 and > 0");
  YACL_ENFORCE(H_vec.size() == original_n && a_vec.size() == original_n &&
                   b_vec.size() == original_n &&
                   G_factors.size() == original_n &&
                   H_factors.size() == original_n,
               "Vector size mismatch");

  transcript.InnerproductDomainSep(original_n);

  size_t lg_n = FloorLog2(original_n);
  std::vector<yacl::crypto::EcPoint> L_vec_out;
  L_vec_out.reserve(lg_n);
  std::vector<yacl::crypto::EcPoint> R_vec_out;
  R_vec_out.reserve(lg_n);

  size_t n = original_n;

  while (n > 1) {
    size_t n_half = n / 2;

    auto a_L = absl::MakeSpan(a_vec.data(), n_half);
    auto a_R = absl::MakeSpan(a_vec.data() + n_half, n_half);
    auto b_L = absl::MakeSpan(b_vec.data(), n_half);
    auto b_R = absl::MakeSpan(b_vec.data() + n_half, n_half);
    auto G_L = absl::MakeSpan(G_vec.data(), n_half);
    auto G_R = absl::MakeSpan(G_vec.data() + n_half, n_half);
    auto H_L = absl::MakeSpan(H_vec.data(), n_half);
    auto H_R = absl::MakeSpan(H_vec.data() + n_half, n_half);

    yacl::math::MPInt c_L = InnerProduct(a_L, b_R, curve);
    yacl::math::MPInt c_R = InnerProduct(a_R, b_L, curve);

    // L and R calculation
    std::vector<yacl::math::MPInt> L_scalars;
    L_scalars.reserve(2 * n_half + 1);
    std::vector<yacl::crypto::EcPoint> L_points;
    L_points.reserve(2 * n_half + 1);

    std::vector<yacl::math::MPInt> R_scalars;
    R_scalars.reserve(2 * n_half + 1);
    std::vector<yacl::crypto::EcPoint> R_points;
    R_points.reserve(2 * n_half + 1);

    if (n == original_n) {  // FIRST ROUND LOGIC
      auto G_factors_L = absl::MakeConstSpan(G_factors.data(), n_half);
      auto G_factors_R = absl::MakeConstSpan(G_factors.data() + n_half, n_half);
      auto H_factors_L = absl::MakeConstSpan(H_factors.data(), n_half);
      auto H_factors_R = absl::MakeConstSpan(H_factors.data() + n_half, n_half);

      // L = <a_L, G_R*G_fact_R> + <b_R, H_L*H_fact_L> + c_L*Q
      for (size_t i = 0; i < n_half; ++i) {
        L_scalars.push_back(a_L[i].MulMod(G_factors_R[i], order));
        L_points.push_back(G_R[i]);
      }
      for (size_t i = 0; i < n_half; ++i) {
        L_scalars.push_back(b_R[i].MulMod(H_factors_L[i], order));
        L_points.push_back(H_L[i]);
      }
      L_scalars.push_back(c_L);
      L_points.push_back(Q);

      // R = <a_R, G_L*G_fact_L> + <b_L, H_R*H_fact_R> + c_R*Q
      for (size_t i = 0; i < n_half; ++i) {
        R_scalars.push_back(a_R[i].MulMod(G_factors_L[i], order));
        R_points.push_back(G_L[i]);
      }
      for (size_t i = 0; i < n_half; ++i) {
        R_scalars.push_back(b_L[i].MulMod(H_factors_R[i], order));
        R_points.push_back(H_R[i]);
      }
      R_scalars.push_back(c_R);
      R_points.push_back(Q);

    } else {  // SUBSEQUENT ROUNDS LOGIC
      // L = <a_L, G_R> + <b_R, H_L> + c_L*Q
      for (size_t i = 0; i < n_half; ++i) {
        L_scalars.push_back(a_L[i]);
      }
      L_points.insert(L_points.end(), G_R.begin(), G_R.end());
      for (size_t i = 0; i < n_half; ++i) {
        L_scalars.push_back(b_R[i]);
      }
      L_points.insert(L_points.end(), H_L.begin(), H_L.end());
      L_scalars.push_back(c_L);
      L_points.push_back(Q);

      // R = <a_R, G_L> + <b_L, H_R> + c_R*Q
      for (size_t i = 0; i < n_half; ++i) {
        R_scalars.push_back(a_R[i]);
      }
      R_points.insert(R_points.end(), G_L.begin(), G_L.end());
      for (size_t i = 0; i < n_half; ++i) {
        R_scalars.push_back(b_L[i]);
      }
      R_points.insert(R_points.end(), H_R.begin(), H_R.end());
      R_scalars.push_back(c_R);
      R_points.push_back(Q);
    }

    yacl::crypto::EcPoint L_point = MultiScalarMul(curve, L_scalars, L_points);
    yacl::crypto::EcPoint R_point = MultiScalarMul(curve, R_scalars, R_points);

    L_vec_out.push_back(L_point);
    R_vec_out.push_back(R_point);

    transcript.AppendPoint("L", L_point, curve);
    transcript.AppendPoint("R", R_point, curve);
    yacl::math::MPInt u = transcript.ChallengeScalar("u", curve);
    yacl::math::MPInt u_inv = u.InvertMod(order);

    // Update vectors for next round
    for (size_t i = 0; i < n_half; ++i) {
      a_vec[i] =
          a_L[i].MulMod(u, order).AddMod(a_R[i].MulMod(u_inv, order), order);
      b_vec[i] =
          b_L[i].MulMod(u_inv, order).AddMod(b_R[i].MulMod(u, order), order);

      if (n == original_n) {  // Update with factors only after first round
        auto G_factors_L = absl::MakeConstSpan(G_factors.data(), n_half);
        auto G_factors_R =
            absl::MakeConstSpan(G_factors.data() + n_half, n_half);
        auto H_factors_L = absl::MakeConstSpan(H_factors.data(), n_half);
        auto H_factors_R =
            absl::MakeConstSpan(H_factors.data() + n_half, n_half);

        yacl::math::MPInt g_l_factor = u_inv.MulMod(G_factors_L[i], order);
        yacl::math::MPInt g_r_factor = u.MulMod(G_factors_R[i], order);
        G_vec[i] =
            MultiScalarMul(curve, {g_l_factor, g_r_factor}, {G_L[i], G_R[i]});

        yacl::math::MPInt h_l_factor = u.MulMod(H_factors_L[i], order);
        yacl::math::MPInt h_r_factor = u_inv.MulMod(H_factors_R[i], order);
        H_vec[i] =
            MultiScalarMul(curve, {h_l_factor, h_r_factor}, {H_L[i], H_R[i]});
      } else {
        G_vec[i] = MultiScalarMul(curve, {u_inv, u}, {G_L[i], G_R[i]});
        H_vec[i] = MultiScalarMul(curve, {u, u_inv}, {H_L[i], H_R[i]});
      }
    }

    n = n_half;
    a_vec.resize(n);
    b_vec.resize(n);
    G_vec.resize(n);
    H_vec.resize(n);
  }

  return InnerProductProof(std::move(L_vec_out), std::move(R_vec_out),
                           std::move(a_vec[0]), std::move(b_vec[0]));
}

std::tuple<std::vector<yacl::math::MPInt>, std::vector<yacl::math::MPInt>,
           std::vector<yacl::math::MPInt>>
InnerProductProof::VerificationScalars(
    size_t n,  // The original vector length (vector size = n)
    SimpleTranscript& transcript,
    const std::shared_ptr<yacl::crypto::EcGroup>& curve) const {
  size_t lg_n = L_vec_.size();  // Number of rounds = log2(n)

  // --- Basic Checks ---
  YACL_ENFORCE(lg_n < 32, "Inner product proof too large (lg_n >= 32)");
  YACL_ENFORCE(n > 0 && (n == (1ULL << lg_n)),
               "Input n must be 2^lg_n and positive");
  YACL_ENFORCE(R_vec_.size() == lg_n, "L_vec and R_vec size mismatch");

  transcript.InnerproductDomainSep(n);

  // --- 1. Recompute challenges u_i from transcript ---
  std::vector<yacl::math::MPInt> u_challenges(lg_n);
  for (size_t i = 0; i < lg_n; ++i) {
    transcript.ValidateAndAppendPoint("L", L_vec_[i], curve);
    transcript.ValidateAndAppendPoint("R", R_vec_[i], curve);
    u_challenges[i] = transcript.ChallengeScalar("u", curve);
  }

  // --- 2. Compute squares of challenges and their inverses ---
  std::vector<yacl::math::MPInt> u_sq(lg_n);
  std::vector<yacl::math::MPInt> u_inv_sq(lg_n);
  std::vector<yacl::math::MPInt> u_inv(lg_n);
  const auto& order = curve->GetOrder();
  for (size_t i = 0; i < lg_n; ++i) {
    u_sq[i] = u_challenges[i].MulMod(u_challenges[i], order);
    u_inv[i] = u_challenges[i].InvertMod(order);
    u_inv_sq[i] = u_inv[i].MulMod(u_inv[i], order);
  }

  // --- 3. Compute s vector ---
  // s_i = product_{j=0}^{k-1} u_{lg_n-j}^(b_j) * product_{j=0}^{k-1}
  // u_{lg_n-j}^{-(1-b_j)} where b_j is j-th bit of i.
  std::vector<yacl::math::MPInt> s(n);
  s[0] = yacl::math::MPInt(1);
  for (const auto& u_inv_i : u_inv) {
    s[0] = s[0].MulMod(u_inv_i, order);
  }

  for (size_t i = 1; i < n; ++i) {
    size_t lg_i = FloorLog2(i);
    size_t k = 1 << lg_i;
    // The challenges are stored in "creation order" as [u_1,...,u_lg_n],
    // so u_{lg(i)+1} is indexed by lg_i
    const auto& u_sq_lg_i = u_sq[lg_n - 1 - lg_i];
    s[i] = s[i - k].MulMod(u_sq_lg_i, order);
  }

  return {u_sq, u_inv_sq, s};
}

bool InnerProductProof::Verify(
    SimpleTranscript& transcript,
    const std::shared_ptr<yacl::crypto::EcGroup>& curve,
    const std::vector<yacl::math::MPInt>& G_factors,  // G_factors
    const std::vector<yacl::math::MPInt>& H_factors,
    const yacl::crypto::EcPoint& P, const yacl::crypto::EcPoint& Q,
    const std::vector<yacl::crypto::EcPoint>& G,
    const std::vector<yacl::crypto::EcPoint>& H) const {
  SPDLOG_DEBUG("InnerProductProof::Verify");

  try {
    size_t n = G.size();
    const auto& order = curve->GetOrder();

    // VerificationScalars  s, u_sq, u_inv_sq
    auto verification_data = this->VerificationScalars(n, transcript, curve);
    const auto& u_sq = std::get<0>(verification_data);
    const auto& u_inv_sq = std::get<1>(verification_data);
    const auto& s = std::get<2>(verification_data);

    // g_times_a_times_s = (a * s_i) * G_factor_i
    std::vector<yacl::math::MPInt> g_times_a_times_s(n);
    for (size_t i = 0; i < n; ++i) {
      g_times_a_times_s[i] = a_.MulMod(s[i], order).MulMod(G_factors[i], order);
    }

    // 1/s[i] is s[!i], where !i is the bitwise negation of i in a field of size
    // n This is equivalent to reversing the s vector.
    auto inv_s = s;
    std::reverse(inv_s.begin(), inv_s.end());

    // h_times_b_div_s = (b * s_inv_i) * H_factor_i
    std::vector<yacl::math::MPInt> h_times_b_div_s(n);
    for (size_t i = 0; i < n; ++i) {
      h_times_b_div_s[i] =
          b_.MulMod(inv_s[i], order).MulMod(H_factors[i], order);
    }

    // -u_i^2 and -u_inv_i^2
    size_t lg_n = u_sq.size();
    std::vector<yacl::math::MPInt> neg_u_sq(lg_n);
    std::vector<yacl::math::MPInt> neg_u_inv_sq(lg_n);
    for (size_t i = 0; i < lg_n; ++i) {
      neg_u_sq[i] = yacl::math::MPInt(0).SubMod(u_sq[i], order);
      neg_u_inv_sq[i] = yacl::math::MPInt(0).SubMod(u_inv_sq[i], order);
    }

    std::vector<yacl::math::MPInt> msm_scalars;
    std::vector<yacl::crypto::EcPoint> msm_points;
    // Pre-allocate memory
    msm_scalars.reserve(1 + n + n + lg_n + lg_n);
    msm_points.reserve(1 + n + n + lg_n + lg_n);

    // Q * (a*b)
    msm_scalars.emplace_back(a_.MulMod(b_, order));
    msm_points.emplace_back(Q);

    // G * (g_times_a_times_s)
    msm_scalars.insert(msm_scalars.end(), g_times_a_times_s.begin(),
                       g_times_a_times_s.end());
    msm_points.insert(msm_points.end(), G.begin(), G.end());

    // H * (h_times_b_div_s)
    msm_scalars.insert(msm_scalars.end(), h_times_b_div_s.begin(),
                       h_times_b_div_s.end());
    msm_points.insert(msm_points.end(), H.begin(), H.end());

    // L * (-u_i^2)
    msm_scalars.insert(msm_scalars.end(), neg_u_sq.begin(), neg_u_sq.end());
    msm_points.insert(msm_points.end(), L_vec_.begin(), L_vec_.end());

    // R * (-u_inv_i^2)
    msm_scalars.insert(msm_scalars.end(), neg_u_inv_sq.begin(),
                       neg_u_inv_sq.end());
    msm_points.insert(msm_points.end(), R_vec_.begin(), R_vec_.end());

    auto expect_P = MultiScalarMul(curve, msm_scalars, msm_points);

    if (curve->PointEqual(expect_P, P)) {
      SPDLOG_DEBUG("P match");
      return true;
    } else {
      SPDLOG_DEBUG("P mismatch");
      return false;
    }
  } catch (const ProofError& e) {
    SPDLOG_DEBUG("Caught ProofError (Type {}): {}",
                 static_cast<int>(e.GetType()), e.what());
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

  return InnerProductProof(std::move(L_vec), std::move(R_vec), std::move(a),
                           std::move(b));
}

}  // namespace examples::zkp