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

#include "yacl/crypto/experimental/zkp/bulletproofs/r1cs/r1cs_verifier.h"

#include <numeric>

#include "yacl/crypto/experimental/zkp/bulletproofs/util.h"

namespace examples::zkp {

R1CSVerifier::R1CSVerifier(SimpleTranscript* transcript,
                           std::shared_ptr<yacl::crypto::EcGroup> curve)
    : transcript_(transcript), curve_(std::move(curve)) {
  transcript->R1csDomainSep();
}

Variable R1CSVerifier::Commit(const yacl::crypto::EcPoint& V) {
  size_t i = V_.size();
  V_.push_back(V);
  transcript_->AppendPoint("V", V, curve_);
  return Variable::Committed(i);
}

SimpleTranscript* R1CSVerifier::Transcript() { return transcript_; }

std::tuple<Variable, Variable, Variable> R1CSVerifier::Multiply(
    LinearCombination left, LinearCombination right) {
  size_t i = num_vars_;
  num_vars_++;

  auto l_var = Variable::MultiplierLeft(i);
  auto r_var = Variable::MultiplierRight(i);
  auto o_var = Variable::MultiplierOutput(i);

  Constrain(left - l_var);
  Constrain(right - r_var);

  return {l_var, r_var, o_var};
}

Result<Variable, R1CSError> R1CSVerifier::Allocate(
    std::optional<yacl::math::MPInt>) {
  if (!pending_multiplier_.has_value()) {
    size_t i = num_vars_;
    num_vars_++;
    pending_multiplier_ = i;
    return Result<Variable, R1CSError>::Ok(Variable::MultiplierLeft(i));
  } else {
    size_t i = pending_multiplier_.value();
    pending_multiplier_ = std::nullopt;
    return Result<Variable, R1CSError>::Ok(Variable::MultiplierRight(i));
  }
}

Result<std::tuple<Variable, Variable, Variable>, R1CSError>
R1CSVerifier::AllocateMultiplier(
    std::optional<std::pair<yacl::math::MPInt, yacl::math::MPInt>>) {
  size_t i = num_vars_;
  num_vars_++;
  return Result<std::tuple<Variable, Variable, Variable>, R1CSError>::Ok(
      {Variable::MultiplierLeft(i), Variable::MultiplierRight(i),
       Variable::MultiplierOutput(i)});
}

Metrics R1CSVerifier::GetMetrics() const {
  return {num_vars_, constraints_.size() + deferred_constraints_.size(),
          constraints_.size(), deferred_constraints_.size()};
}

void R1CSVerifier::Constrain(LinearCombination lc) {
  constraints_.push_back(std::move(lc));
}

Result<void, R1CSError> R1CSVerifier::SpecifyRandomizedConstraints(
    RandomizedCallback callback) {
  deferred_constraints_.push_back(callback);
  return Result<void, R1CSError>::Ok();
}

Result<void, R1CSError> R1CSVerifier::CreateRandomizedConstraints() {
  pending_multiplier_ = std::nullopt;
  if (deferred_constraints_.empty()) {
    transcript_->R1cs1phaseDomainSep();
  } else {
    transcript_->R1cs2phaseDomainSep();
    RandomizedVerifier random_verifier(this);
    for (const auto& callback : deferred_constraints_) {
      auto result = callback(&random_verifier);
      if (!result.IsOk()) return result;
    }
  }
  deferred_constraints_.clear();
  return Result<void, R1CSError>::Ok();
}

std::tuple<std::vector<yacl::math::MPInt>, std::vector<yacl::math::MPInt>,
           std::vector<yacl::math::MPInt>, std::vector<yacl::math::MPInt>,
           yacl::math::MPInt>
R1CSVerifier::FlattenedConstraints(const yacl::math::MPInt& z) const {
  size_t n = num_vars_;
  size_t m = V_.size();

  std::vector<yacl::math::MPInt> wL(n, yacl::math::MPInt(0));
  std::vector<yacl::math::MPInt> wR(n, yacl::math::MPInt(0));
  std::vector<yacl::math::MPInt> wO(n, yacl::math::MPInt(0));
  std::vector<yacl::math::MPInt> wV(m, yacl::math::MPInt(0));
  yacl::math::MPInt wc(0);

  yacl::math::MPInt exp_z = z;
  for (const auto& lc : constraints_) {
    for (const auto& term : lc.terms) {
      switch (term.first.type) {
        case VariableType::MultiplierLeft:
          wL[term.first.index] += exp_z * term.second;
          break;
        case VariableType::MultiplierRight:
          wR[term.first.index] += exp_z * term.second;
          break;
        case VariableType::MultiplierOutput:
          wO[term.first.index] += exp_z * term.second;
          break;
        case VariableType::Committed:
          wV[term.first.index] -= exp_z * term.second;
          break;
        case VariableType::One:
          wc -= exp_z * term.second;
          break;
      }
    }
    exp_z *= z;
  }
  return {wL, wR, wO, wV, wc};
}

Result<void, R1CSError> R1CSVerifier::Verify(
    const R1CSProof& proof, const PedersenGens* pc_gens,
    const BulletproofGens* bp_gens) const {
  auto non_const_this = const_cast<R1CSVerifier*>(this);
  auto curve = pc_gens->GetCurve();
  const auto& order = curve->GetOrder();

  transcript_->AppendU64("m", V_.size());
  size_t n1 = num_vars_;

  transcript_->AppendPoint("A_I1", proof.A_I1, curve);
  transcript_->AppendPoint("A_O1", proof.A_O1, curve);
  transcript_->AppendPoint("S1", proof.S1, curve);

  auto res = non_const_this->CreateRandomizedConstraints();
  if (!res.IsOk()) {
    return res;
  }

  size_t n = num_vars_;
  size_t padded_n = NextPowerOfTwo(n);

  YACL_ENFORCE(bp_gens->gens_capacity() >= padded_n,
               "Invalid generators length");
  auto gens_share = bp_gens->Share(0);

  transcript_->AppendPoint("A_I2", proof.A_I2, curve);
  transcript_->AppendPoint("A_O2", proof.A_O2, curve);
  transcript_->AppendPoint("S2", proof.S2, curve);

  auto y = transcript_->ChallengeScalar("y", curve);
  auto z = transcript_->ChallengeScalar("z", curve);

  transcript_->AppendPoint("T_1", proof.T_1, curve);
  transcript_->AppendPoint("T_3", proof.T_3, curve);
  transcript_->AppendPoint("T_4", proof.T_4, curve);
  transcript_->AppendPoint("T_5", proof.T_5, curve);
  transcript_->AppendPoint("T_6", proof.T_6, curve);

  auto u = transcript_->ChallengeScalar("u", curve);
  auto x = transcript_->ChallengeScalar("x", curve);

  transcript_->AppendScalar("t_x", proof.t_x);
  transcript_->AppendScalar("t_x_blinding", proof.t_x_blinding);
  transcript_->AppendScalar("e_blinding", proof.e_blinding);

  auto w = transcript_->ChallengeScalar("w", curve);

  auto [wL, wR, wO, wV, wc] = FlattenedConstraints(z);

  auto ipp_scalars =
      proof.ipp_proof.VerificationScalars(padded_n, *transcript_, curve);
  const auto& u_sq = std::get<0>(ipp_scalars);
  const auto& u_inv_sq = std::get<1>(ipp_scalars);
  const auto& s = std::get<2>(ipp_scalars);

  const auto& a_ipp = proof.ipp_proof.GetA();
  const auto& b_ipp = proof.ipp_proof.GetB();

  auto r = transcript_->ChallengeScalar("r", curve);

  size_t msm_size =
      13 + V_.size() + (2 * padded_n) + u_sq.size() + u_inv_sq.size();
  std::vector<yacl::math::MPInt> msm_scalars;
  std::vector<yacl::crypto::EcPoint> msm_points;
  msm_scalars.reserve(msm_size);
  msm_points.reserve(msm_size);

  auto x_sq = x.MulMod(x, order);
  auto x_3 = x_sq.MulMod(x, order);

  msm_scalars.push_back(x);
  msm_points.push_back(proof.A_I1);
  msm_scalars.push_back(x_sq);
  msm_points.push_back(proof.A_O1);
  msm_scalars.push_back(x_3);
  msm_points.push_back(proof.S1);
  msm_scalars.push_back(u.MulMod(x, order));
  msm_points.push_back(proof.A_I2);
  msm_scalars.push_back(u.MulMod(x_sq, order));
  msm_points.push_back(proof.A_O2);
  msm_scalars.push_back(u.MulMod(x_3, order));
  msm_points.push_back(proof.S2);

  auto r_x_sq = r.MulMod(x_sq, order);
  for (const auto& wV_i : wV) {
    msm_scalars.push_back(r_x_sq.MulMod(wV_i, order));
  }
  msm_points.insert(msm_points.end(), V_.begin(), V_.end());

  auto x_4 = x_sq.MulMod(x_sq, order);
  auto x_5 = x_4.MulMod(x, order);
  auto x_6 = x_3.MulMod(x_3, order);
  msm_scalars.push_back(r.MulMod(x, order));
  msm_points.push_back(proof.T_1);
  msm_scalars.push_back(r.MulMod(x_3, order));
  msm_points.push_back(proof.T_3);
  msm_scalars.push_back(r.MulMod(x_4, order));
  msm_points.push_back(proof.T_4);
  msm_scalars.push_back(r.MulMod(x_5, order));
  msm_points.push_back(proof.T_5);
  msm_scalars.push_back(r.MulMod(x_6, order));
  msm_points.push_back(proof.T_6);

  auto y_inv = y.InvertMod(order);
  auto y_inv_pows = ExpIterVector(y_inv, padded_n, curve);
  std::vector<yacl::math::MPInt> yneg_wR(n);
  for (size_t i = 0; i < n; ++i) {
    yneg_wR[i] = wR[i].MulMod(y_inv_pows[i], order);
  }
  auto delta = InnerProduct(absl::MakeSpan(wL), absl::MakeSpan(yneg_wR), curve);

  // B and B_blinding terms
  auto term1 =
      w.MulMod(proof.t_x.SubMod(a_ipp.MulMod(b_ipp, order), order), order);
  auto term2 = x_sq.MulMod(wc.AddMod(delta, order), order);
  term2 = r.MulMod(term2.SubMod(proof.t_x, order), order);
  msm_scalars.push_back(term1.AddMod(term2, order));
  msm_points.push_back(pc_gens->B);

  auto term3 = -proof.e_blinding;
  term3 = term3.SubMod(r.MulMod(proof.t_x_blinding, order), order);
  msm_scalars.push_back(term3.Mod(order));
  msm_points.push_back(pc_gens->B_blinding);

  auto s_rev = s;
  std::reverse(s_rev.begin(), s_rev.end());

  size_t n2 = n - n1;
  size_t pad = padded_n - n;
  std::vector<yacl::math::MPInt> u_for_g(n1, yacl::math::MPInt(1));
  if (n2 + pad > 0) {
    u_for_g.insert(u_for_g.end(), n2 + pad, u);
  }

  auto G_padded = gens_share.G(padded_n);
  for (size_t i = 0; i < padded_n; ++i) {
    auto wR_i = (i < n) ? yneg_wR[i] : yacl::math::MPInt(0);
    auto g_s = x.MulMod(wR_i, order).SubMod(a_ipp.MulMod(s[i], order), order);
    msm_scalars.push_back(u_for_g[i].MulMod(g_s, order));
    msm_points.push_back(G_padded[i]);
  }

  auto H_padded = gens_share.H(padded_n);
  for (size_t i = 0; i < padded_n; ++i) {
    auto wL_i = (i < n) ? wL[i] : yacl::math::MPInt(0);
    auto wO_i = (i < n) ? wO[i] : yacl::math::MPInt(0);
    auto h_s = x.MulMod(wL_i, order).AddMod(wO_i, order);
    h_s = h_s.SubMod(b_ipp.MulMod(s_rev[i], order), order);
    h_s = y_inv_pows[i].MulMod(h_s, order);
    h_s = h_s.SubMod(yacl::math::MPInt(1), order);
    msm_scalars.push_back(u_for_g[i].MulMod(h_s, order));
    msm_points.push_back(H_padded[i]);
  }

  const auto& L_vec = proof.ipp_proof.GetLVec();
  for (size_t i = 0; i < u_sq.size(); ++i) {
    msm_scalars.push_back(u_sq[i]);
    msm_points.push_back(L_vec[i]);
  }

  const auto& R_vec = proof.ipp_proof.GetRVec();
  for (size_t i = 0; i < u_inv_sq.size(); ++i) {
    msm_scalars.push_back(u_inv_sq[i]);
    msm_points.push_back(R_vec[i]);
  }

  YACL_ENFORCE(msm_scalars.size() == msm_points.size(),
               "Final MSM vector size mismatch: scalars={}, points={}",
               msm_scalars.size(), msm_points.size());

  auto mega_check_point = MultiScalarMul(curve, msm_scalars, msm_points);

  if (!curve->IsInfinity(mega_check_point)) {
    return Result<void, R1CSError>::Err(
        R1CSError(R1CSError::Code::VerificationError));
  }

  return Result<void, R1CSError>::Ok();
}

std::tuple<Variable, Variable, Variable> RandomizedVerifier::Multiply(
    LinearCombination left, LinearCombination right) {
  return verifier_->Multiply(std::move(left), std::move(right));
}

Result<Variable, R1CSError> RandomizedVerifier::Allocate(
    std::optional<yacl::math::MPInt> assignment) {
  return verifier_->Allocate(std::move(assignment));
}

void RandomizedVerifier::Constrain(LinearCombination lc) {
  verifier_->Constrain(std::move(lc));
}

yacl::math::MPInt RandomizedVerifier::ChallengeScalar(absl::string_view label) {
  return verifier_->Transcript()->ChallengeScalar(label, verifier_->curve_);
}

}  // namespace examples::zkp