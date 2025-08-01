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

#include "yacl/crypto/experimental/zkp/bulletproofs/r1cs/r1cs_prover.h"

#include <numeric>

#include "yacl/crypto/experimental/zkp/bulletproofs/ipa/inner_product_proof.h"
#include "yacl/crypto/experimental/zkp/bulletproofs/util.h"
#include "yacl/crypto/rand/rand.h"

namespace examples::zkp {

// R1CSProver Implementation
// ===================================
R1CSProver::R1CSProver(SimpleTranscript* transcript,
                       const PedersenGens* pc_gens)
    : transcript_(transcript),
      pc_gens_(pc_gens),
      pending_multiplier_(std::nullopt) {
  transcript->R1csDomainSep();
}

std::pair<yacl::crypto::EcPoint, Variable> R1CSProver::Commit(
    yacl::math::MPInt v, yacl::math::MPInt v_blinding) {
  size_t i = v_.size();
  v_.push_back(v);
  v_blinding_.push_back(v_blinding);

  auto V = pc_gens_->Commit(v, v_blinding);
  transcript_->AppendPoint("V", V, pc_gens_->GetCurve());
  return {V, Variable::Committed(i)};
}

SimpleTranscript* R1CSProver::Transcript() { return transcript_; }

std::tuple<Variable, Variable, Variable> R1CSProver::Multiply(
    LinearCombination left, LinearCombination right) {
  auto l = Eval(left);
  auto r = Eval(right);
  auto o = l * r;

  size_t i = a_L_.size();
  auto l_var = Variable::MultiplierLeft(i);
  auto r_var = Variable::MultiplierRight(i);
  auto o_var = Variable::MultiplierOutput(i);
  a_L_.push_back(l);
  a_R_.push_back(r);
  a_O_.push_back(o);

  Constrain(left - l_var);
  Constrain(right - r_var);

  return {l_var, r_var, o_var};
}

Result<Variable, R1CSError> R1CSProver::Allocate(
    std::optional<yacl::math::MPInt> assignment) {
  if (!assignment.has_value()) {
    return Result<Variable, R1CSError>::Err(
        R1CSError(R1CSError::Code::MissingAssignment));
  }
  auto scalar = assignment.value();

  if (!pending_multiplier_.has_value()) {
    size_t i = a_L_.size();
    pending_multiplier_ = i;
    a_L_.push_back(scalar);
    a_R_.emplace_back(0);  // Pad with 0
    a_O_.emplace_back(0);  // Pad with 0
    return Result<Variable, R1CSError>::Ok(Variable::MultiplierLeft(i));
  } else {
    size_t i = pending_multiplier_.value();
    pending_multiplier_ = std::nullopt;
    a_R_[i] = scalar;
    a_O_[i] = a_L_[i] * a_R_[i];
    return Result<Variable, R1CSError>::Ok(Variable::MultiplierRight(i));
  }
}

Result<std::tuple<Variable, Variable, Variable>, R1CSError>
R1CSProver::AllocateMultiplier(
    std::optional<std::pair<yacl::math::MPInt, yacl::math::MPInt>>
        input_assignments) {
  if (!input_assignments.has_value()) {
    return Result<std::tuple<Variable, Variable, Variable>, R1CSError>::Err(
        R1CSError(R1CSError::Code::MissingAssignment));
  }
  auto [l, r] = input_assignments.value();
  auto o = l * r;

  size_t i = a_L_.size();
  a_L_.push_back(l);
  a_R_.push_back(r);
  a_O_.push_back(o);

  return Result<std::tuple<Variable, Variable, Variable>, R1CSError>::Ok(
      {Variable::MultiplierLeft(i), Variable::MultiplierRight(i),
       Variable::MultiplierOutput(i)});
}

Metrics R1CSProver::GetMetrics() const {
  return {a_L_.size(), constraints_.size() + deferred_constraints_.size(),
          constraints_.size(), deferred_constraints_.size()};
}

void R1CSProver::Constrain(LinearCombination lc) {
  constraints_.push_back(std::move(lc));
}

Result<void> R1CSProver::SpecifyRandomizedConstraints(
    RandomizedCallback callback) {
  deferred_constraints_.push_back(callback);
  return Result<void>::Ok();
}

yacl::math::MPInt R1CSProver::Eval(const LinearCombination& lc) const {
  yacl::math::MPInt acc(0);
  for (const auto& term : lc.getTerms()) {
    auto var_value = yacl::math::MPInt(0);
    switch (term.first.type) {
      case VariableType::Committed:
        var_value = v_[term.first.index];
        break;
      case VariableType::MultiplierLeft:
        var_value = a_L_[term.first.index];
        break;
      case VariableType::MultiplierRight:
        var_value = a_R_[term.first.index];
        break;
      case VariableType::MultiplierOutput:
        var_value = a_O_[term.first.index];
        break;
      case VariableType::One:
        var_value = yacl::math::MPInt(1);
        break;
    }
    acc += term.second * var_value;
  }
  return acc;
}

Result<void> R1CSProver::CreateRandomizedConstraints() {
  pending_multiplier_ = std::nullopt;  // Clear pending state
  if (deferred_constraints_.empty()) {
    transcript_->R1cs1phaseDomainSep();
  } else {
    transcript_->R1cs2phaseDomainSep();
    RandomizedProver random_prover(this);
    for (const auto& callback : deferred_constraints_) {
      auto result = callback(&random_prover);
      if (!result.IsOk()) return result;
    }
  }
  deferred_constraints_.clear();
  return Result<void>::Ok();
}

std::tuple<std::vector<yacl::math::MPInt>, std::vector<yacl::math::MPInt>,
           std::vector<yacl::math::MPInt>, std::vector<yacl::math::MPInt>>
R1CSProver::FlattenedConstraints(const yacl::math::MPInt& z) const {
  size_t n = a_L_.size();
  size_t m = v_.size();

  std::vector<yacl::math::MPInt> wL(n, yacl::math::MPInt(0));
  std::vector<yacl::math::MPInt> wR(n, yacl::math::MPInt(0));
  std::vector<yacl::math::MPInt> wO(n, yacl::math::MPInt(0));
  std::vector<yacl::math::MPInt> wV(m, yacl::math::MPInt(0));

  yacl::math::MPInt exp_z = z;
  for (const auto& lc : constraints_) {
    for (const auto& term : lc.getTerms()) {
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
          break;  // Prover ignores constant term
      }
    }
    exp_z *= z;
  }
  return {wL, wR, wO, wV};
}

Result<R1CSProof, R1CSError> R1CSProver::Prove(
    const BulletproofGens* bp_gens) const {
  auto non_const_this = const_cast<R1CSProver*>(this);
  auto curve = pc_gens_->GetCurve();
  auto order = curve->GetOrder();

  // Phase 1: commit to non-randomized variables
  transcript_->AppendU64("m", v_.size());
  size_t n1 = a_L_.size();

  YACL_ENFORCE(bp_gens->gens_capacity() >= n1,
               "Invalid generators length for phase 1");
  auto gens_share = bp_gens->Share(0);

  auto i_blinding1 = CreateDummyScalar(curve);
  auto o_blinding1 = CreateDummyScalar(curve);
  auto s_blinding1 = CreateDummyScalar(curve);

  auto G1 = gens_share.G(n1);
  auto H1 = gens_share.H(n1);

  // A_I1 = <a_L, G> + <a_R, H> + i_blinding1 * B_blinding
  std::vector<yacl::math::MPInt> msm_scalars;
  std::vector<yacl::crypto::EcPoint> msm_points;
  msm_scalars.reserve(1 + a_L_.size() + a_R_.size());
  msm_points.reserve(1 + a_L_.size() + a_R_.size());

  msm_scalars.push_back(i_blinding1);
  msm_points.push_back(pc_gens_->B_blinding);
  // Add all scalars first
  msm_scalars.insert(msm_scalars.end(), a_L_.begin(), a_L_.end());
  msm_scalars.insert(msm_scalars.end(), a_R_.begin(), a_R_.end());
  // Then add all corresponding points
  msm_points.insert(msm_points.end(), G1.begin(), G1.end());
  msm_points.insert(msm_points.end(), H1.begin(), H1.end());
  auto A_I1 = MultiScalarMul(curve, msm_scalars, msm_points);

  // A_O1 = <a_O, G> + o_blinding1 * B_blinding

  msm_scalars.assign({o_blinding1});
  msm_points.assign({pc_gens_->B_blinding});
  msm_scalars.insert(msm_scalars.end(), a_O_.begin(), a_O_.end());
  msm_points.insert(msm_points.end(), G1.begin(), G1.end());
  auto A_O1 = MultiScalarMul(curve, msm_scalars, msm_points);

  // s_L1 and s_R1 generation
  std::vector<yacl::math::MPInt> s_L1, s_R1;
  for (size_t i = 0; i < n1; ++i) {
    s_L1.push_back(CreateDummyScalar(curve));
    s_R1.push_back(CreateDummyScalar(curve));
  }

  // S1 = <s_L1, G> + <s_R1, H> + s_blinding1 * B_blinding
  msm_scalars.assign({s_blinding1});
  msm_points.assign({pc_gens_->B_blinding});
  msm_scalars.insert(msm_scalars.end(), s_L1.begin(), s_L1.end());
  msm_scalars.insert(msm_scalars.end(), s_R1.begin(), s_R1.end());
  msm_points.insert(msm_points.end(), G1.begin(), G1.end());
  msm_points.insert(msm_points.end(), H1.begin(), H1.end());
  auto S1 = MultiScalarMul(curve, msm_scalars, msm_points);

  transcript_->AppendPoint("A_I1", A_I1, curve);
  transcript_->AppendPoint("A_O1", A_O1, curve);
  transcript_->AppendPoint("S1", S1, curve);

  // Phase 2: create randomized constraints and commit
  auto res = non_const_this->CreateRandomizedConstraints();
  if (!res.IsOk()) {
    return Result<R1CSProof, R1CSError>::Err(R1CSError(res.Error()));
  }

  size_t n = a_L_.size();
  size_t n2 = n - n1;
  size_t padded_n = NextPowerOfTwo(n);

  YACL_ENFORCE(bp_gens->gens_capacity() >= padded_n,
               "Invalid generators length for padded size");

  yacl::crypto::EcPoint A_I2, A_O2, S2;
  yacl::math::MPInt i_blinding2(0), o_blinding2(0), s_blinding2(0);
  std::vector<yacl::math::MPInt> s_L2, s_R2;

  if (n2 > 0) {
    i_blinding2 = CreateDummyScalar(curve);
    o_blinding2 = CreateDummyScalar(curve);
    s_blinding2 = CreateDummyScalar(curve);

    auto G_full = gens_share.G(n);
    auto H_full = gens_share.H(n);

    std::vector<yacl::crypto::EcPoint> G2(G_full.begin() + n1, G_full.end());
    std::vector<yacl::crypto::EcPoint> H2(H_full.begin() + n1, H_full.end());

    YACL_ENFORCE(G2.size() == n2, "G2 vector has incorrect size");
    YACL_ENFORCE(H2.size() == n2, "H2 vector has incorrect size");

    // A_I2 = <a_L[n1:], G[n1:]> + <a_R[n1:], H[n1:]> + i_blinding2 * B_blinding
    msm_scalars.assign({i_blinding2});
    msm_points.assign({pc_gens_->B_blinding});
    msm_scalars.insert(msm_scalars.end(), a_L_.begin() + n1, a_L_.end());
    msm_scalars.insert(msm_scalars.end(), a_R_.begin() + n1, a_R_.end());
    msm_points.insert(msm_points.end(), G2.begin(), G2.end());
    msm_points.insert(msm_points.end(), H2.begin(), H2.end());
    A_I2 = MultiScalarMul(curve, msm_scalars, msm_points);

    // A_O2 = <a_O[n1:], G[n1:]> + o_blinding2 * B_blinding
    msm_scalars.assign({o_blinding2});
    msm_points.assign({pc_gens_->B_blinding});
    msm_scalars.insert(msm_scalars.end(), a_O_.begin() + n1, a_O_.end());
    msm_points.insert(msm_points.end(), G2.begin(), G2.end());
    A_O2 = MultiScalarMul(curve, msm_scalars, msm_points);

    // s_L2, s_R2 generation
    s_L2.reserve(n2);
    s_R2.reserve(n2);
    for (size_t i = 0; i < n2; ++i) {
      s_L2.push_back(CreateDummyScalar(curve));
      s_R2.push_back(CreateDummyScalar(curve));
    }

    // S2 = <s_L2, G[n1:]> + <s_R2, H[n1:]> + s_blinding2 * B_blinding
    msm_scalars.assign({s_blinding2});
    msm_points.assign({pc_gens_->B_blinding});
    msm_scalars.insert(msm_scalars.end(), s_L2.begin(), s_L2.end());
    msm_scalars.insert(msm_scalars.end(), s_R2.begin(), s_R2.end());
    msm_points.insert(msm_points.end(), G2.begin(), G2.end());
    msm_points.insert(msm_points.end(), H2.begin(), H2.end());
    S2 = MultiScalarMul(curve, msm_scalars, msm_points);
  } else {
    A_I2 = curve->MulBase(yacl::math::MPInt(0));
    A_O2 = curve->MulBase(yacl::math::MPInt(0));
    S2 = curve->MulBase(yacl::math::MPInt(0));
  }

  transcript_->AppendPoint("A_I2", A_I2, curve);
  transcript_->AppendPoint("A_O2", A_O2, curve);
  transcript_->AppendPoint("S2", S2, curve);

  auto y = transcript_->ChallengeScalar("y", curve);
  auto z = transcript_->ChallengeScalar("z", curve);

  auto [wL, wR, wO, wV] = FlattenedConstraints(z);

  VecPoly3 l_poly(n), r_poly(n);
  auto y_inv = y.InvertMod(order);
  auto y_inv_pows = ExpIterVector(y_inv, padded_n, curve);
  auto y_pows = ExpIterVector(y, padded_n, curve);

  std::vector<yacl::math::MPInt> s_L_full, s_R_full;
  s_L_full.insert(s_L_full.end(), s_L1.begin(), s_L1.end());
  s_L_full.insert(s_L_full.end(), s_L2.begin(), s_L2.end());
  s_R_full.insert(s_R_full.end(), s_R1.begin(), s_R1.end());
  s_R_full.insert(s_R_full.end(), s_R2.begin(), s_R2.end());

  for (size_t i = 0; i < n; ++i) {
    l_poly.T1[i] = a_L_[i] + y_inv_pows[i] * wR[i];
    l_poly.T2[i] = a_O_[i];
    l_poly.T3[i] = s_L_full[i];

    r_poly.T0[i] = wO[i] - y_pows[i];
    r_poly.T1[i] = y_pows[i] * a_R_[i] + wL[i];
    r_poly.T3[i] = y_pows[i] * s_R_full[i];
  }

  auto t_poly = SpecialInnerProduct(l_poly, r_poly, curve);

  auto t_1_blinding = CreateDummyScalar(curve);
  auto t_3_blinding = CreateDummyScalar(curve);
  auto t_4_blinding = CreateDummyScalar(curve);
  auto t_5_blinding = CreateDummyScalar(curve);
  auto t_6_blinding = CreateDummyScalar(curve);

  auto T_1 = pc_gens_->Commit(t_poly.T1, t_1_blinding);
  auto T_3 = pc_gens_->Commit(t_poly.T3, t_3_blinding);
  auto T_4 = pc_gens_->Commit(t_poly.T4, t_4_blinding);
  auto T_5 = pc_gens_->Commit(t_poly.T5, t_5_blinding);
  auto T_6 = pc_gens_->Commit(t_poly.T6, t_6_blinding);

  transcript_->AppendPoint("T_1", T_1, curve);
  transcript_->AppendPoint("T_3", T_3, curve);
  transcript_->AppendPoint("T_4", T_4, curve);
  transcript_->AppendPoint("T_5", T_5, curve);
  transcript_->AppendPoint("T_6", T_6, curve);

  auto u = transcript_->ChallengeScalar("u", curve);
  auto x = transcript_->ChallengeScalar("x", curve);

  yacl::math::MPInt t_2_blinding =
      InnerProduct(absl::MakeSpan(wV), absl::MakeSpan(v_blinding_), curve);

  Poly6 t_blinding_poly;
  t_blinding_poly.T1 = t_1_blinding;
  t_blinding_poly.T2 = t_2_blinding;
  t_blinding_poly.T3 = t_3_blinding;
  t_blinding_poly.T4 = t_4_blinding;
  t_blinding_poly.T5 = t_5_blinding;
  t_blinding_poly.T6 = t_6_blinding;

  auto t_x = t_poly.Eval(x, curve);
  auto t_x_blinding = t_blinding_poly.Eval(x, curve);

  auto l_vec = l_poly.Eval(x, curve);
  l_vec.resize(padded_n, yacl::math::MPInt(0));

  auto r_vec = r_poly.Eval(x, curve);
  r_vec.resize(padded_n, yacl::math::MPInt(0));
  for (size_t i = n; i < padded_n; ++i) {
    r_vec[i] = -y_pows[i];
  }

  yacl::math::MPInt i_blinding = i_blinding1 + u * i_blinding2;
  yacl::math::MPInt o_blinding = o_blinding1 + u * o_blinding2;
  yacl::math::MPInt s_blinding = s_blinding1 + u * s_blinding2;

  yacl::math::MPInt x_sq = x * x;
  yacl::math::MPInt e_blinding =
      x * (i_blinding + x * (o_blinding + x * s_blinding));

  transcript_->AppendScalar("t_x", t_x);
  transcript_->AppendScalar("t_x_blinding", t_x_blinding);
  transcript_->AppendScalar("e_blinding", e_blinding);

  auto w = transcript_->ChallengeScalar("w", curve);
  auto Q_ipp = curve->Mul(pc_gens_->B, w);

  std::vector<yacl::math::MPInt> G_factors_ipp(padded_n, yacl::math::MPInt(1));
  for (size_t i = n1; i < padded_n; ++i) {
    G_factors_ipp[i] = u;
  }

  std::vector<yacl::math::MPInt> H_factors_ipp = y_inv_pows;
  for (size_t i = 0; i < padded_n; ++i) {
    H_factors_ipp[i] *= G_factors_ipp[i];
  }

  auto ipp_proof = InnerProductProof::Create(
      *transcript_, curve, Q_ipp, G_factors_ipp, H_factors_ipp,
      gens_share.G(padded_n), gens_share.H(padded_n), std::move(l_vec),
      std::move(r_vec));

  return Result<R1CSProof, R1CSError>::Ok(
      R1CSProof{A_I1, A_O1, S1, A_I2, A_O2, S2, T_1, T_3, T_4, T_5, T_6, t_x,
                t_x_blinding, e_blinding, std::move(ipp_proof)});
}

std::tuple<Variable, Variable, Variable> RandomizedProver::Multiply(
    LinearCombination left, LinearCombination right) {
  return prover_->Multiply(std::move(left), std::move(right));
}

Result<Variable, R1CSError> RandomizedProver::Allocate(
    std::optional<yacl::math::MPInt> assignment) {
  return prover_->Allocate(std::move(assignment));
}

void RandomizedProver::Constrain(LinearCombination lc) {
  prover_->Constrain(std::move(lc));
}

yacl::math::MPInt RandomizedProver::ChallengeScalar(absl::string_view label) {
  return prover_->Transcript()->ChallengeScalar(label,
                                                prover_->pc_gens_->GetCurve());
}

}  // namespace examples::zkp