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

#include "yacl/crypto/experimental/zkp/bulletproofs/range_proof/range_proof_internal.h"
#include "yacl/crypto/rand/rand.h"

// Bring the internal classes into the current namespace for easier use
namespace examples::zkp {
using namespace ::examples::zkp::internal;

// =============================================================================
// Party Implementation (Internal MPC logic)
// =============================================================================

Result<PartyAwaitingPosition> Party::New(
    std::shared_ptr<const BulletproofGens> bp_gens,
    std::shared_ptr<const PedersenGens> pc_gens, uint64_t v,
    const yacl::math::MPInt& v_blinding, size_t n) {
  if (!(n == 8 || n == 16 || n == 32 || n == 64)) {
    return Result<PartyAwaitingPosition>::Err(
        ProofError(ProofError::Code::InvalidBitsize));
  }
  if (bp_gens->gens_capacity() < n) {
    return Result<PartyAwaitingPosition>::Err(
        ProofError(ProofError::Code::InvalidGeneratorsLength));
  }

  yacl::crypto::EcPoint V = pc_gens->Commit(yacl::math::MPInt(v), v_blinding);
  return Result<PartyAwaitingPosition>::Ok(PartyAwaitingPosition(
      std::move(bp_gens), std::move(pc_gens), n, v, v_blinding, std::move(V)));
}

PartyAwaitingPosition::PartyAwaitingPosition(
    std::shared_ptr<const BulletproofGens> bp_gens,
    std::shared_ptr<const PedersenGens> pc_gens, size_t n, uint64_t v,
    yacl::math::MPInt v_blinding, yacl::crypto::EcPoint V)
    : bp_gens_(std::move(bp_gens)),
      pc_gens_(std::move(pc_gens)),
      n_(n),
      v_(v),
      v_blinding_(std::move(v_blinding)),
      V_(std::move(V)) {}

Result<std::pair<PartyAwaitingBitChallenge, BitCommitment>>
PartyAwaitingPosition::AssignPosition(
    const std::shared_ptr<yacl::crypto::EcGroup>& curve, size_t j) {
  if (bp_gens_->party_capacity() <= j) {
    return Result<std::pair<PartyAwaitingBitChallenge, BitCommitment>>::Err(
        ProofError(ProofError::Code::InvalidGeneratorsLength));
  }

  auto bgs = bp_gens_->Share(j);
  yacl::math::MPInt a_blinding = CreateRandomScalar(curve);
  yacl::crypto::EcPoint A = curve->Mul(pc_gens_->B_blinding, a_blinding);

  auto G_j = bgs.G(n_);
  auto H_j = bgs.H(n_);

  for (size_t i = 0; i < n_; ++i) {
    if (((v_ >> i) & 1) == 0) {
      A = curve->Sub(A, H_j[i]);
    } else {
      A = curve->Add(A, G_j[i]);
    }
  }

  yacl::math::MPInt s_blinding = CreateRandomScalar(curve);
  std::vector<yacl::math::MPInt> s_L(n_), s_R(n_);
  for (size_t i = 0; i < n_; ++i) {
    s_L[i] = CreateRandomScalar(curve);
    s_R[i] = CreateRandomScalar(curve);
  }

  std::vector<yacl::math::MPInt> S_scalars;
  std::vector<yacl::crypto::EcPoint> S_points;
  S_scalars.reserve(1 + n_ + n_);
  S_points.reserve(1 + n_ + n_);
  S_scalars.push_back(s_blinding);
  S_points.push_back(pc_gens_->B_blinding);
  S_scalars.insert(S_scalars.end(), s_L.begin(), s_L.end());
  S_points.insert(S_points.end(), G_j.begin(), G_j.end());
  S_scalars.insert(S_scalars.end(), s_R.begin(), s_R.end());
  S_points.insert(S_points.end(), H_j.begin(), H_j.end());
  yacl::crypto::EcPoint S = MultiScalarMul(curve, S_scalars, S_points);

  BitCommitment bit_commitment{V_, A, S};
  PartyAwaitingBitChallenge next_state(
      n_, v_, std::move(v_blinding_), j, pc_gens_, std::move(a_blinding),
      std::move(s_blinding), std::move(s_L), std::move(s_R));

  return Result<std::pair<PartyAwaitingBitChallenge, BitCommitment>>::Ok(
      {std::move(next_state), bit_commitment});
}

PartyAwaitingBitChallenge::PartyAwaitingBitChallenge(
    size_t n, uint64_t v, yacl::math::MPInt v_blinding, size_t j,
    std::shared_ptr<const PedersenGens> pc_gens, yacl::math::MPInt a_blinding,
    yacl::math::MPInt s_blinding, std::vector<yacl::math::MPInt> s_L,
    std::vector<yacl::math::MPInt> s_R)
    : n_(n),
      v_(v),
      v_blinding_(std::move(v_blinding)),
      j_(j),
      pc_gens_(std::move(pc_gens)),
      a_blinding_(std::move(a_blinding)),
      s_blinding_(std::move(s_blinding)),
      s_L_(std::move(s_L)),
      s_R_(std::move(s_R)) {}

std::pair<PartyAwaitingPolyChallenge, PolyCommitment>
PartyAwaitingBitChallenge::ApplyChallenge(
    const std::shared_ptr<yacl::crypto::EcGroup>& curve,
    const BitChallenge& vc) {
  const auto& order = curve->GetOrder();
  yacl::math::MPInt one(1);
  yacl::math::MPInt two(2);

  yacl::math::MPInt y_jn = ScalarExp(vc.y, j_ * n_, curve);
  yacl::math::MPInt offset_z = ScalarExp(vc.z, j_, curve);
  yacl::math::MPInt offset_zz =
      vc.z.MulMod(vc.z, order).MulMod(offset_z, order);

  VecPoly1 l_poly = VecPoly1::Zero(n_);
  VecPoly1 r_poly = VecPoly1::Zero(n_);

  auto y_pows = ExpIterVector(vc.y, n_, curve);
  auto two_pows = ExpIterVector(two, n_, curve);

  for (size_t i = 0; i < n_; ++i) {
    yacl::math::MPInt a_L_i((v_ >> i) & 1);
    yacl::math::MPInt a_R_i = a_L_i.SubMod(one, order);

    l_poly.vec0[i] = a_L_i.SubMod(vc.z, order);
    l_poly.vec1[i] = s_L_[i];

    yacl::math::MPInt r0_term1 =
        y_pows[i].MulMod(a_R_i.AddMod(vc.z, order), order);
    r0_term1 = r0_term1.MulMod(y_jn, order);
    yacl::math::MPInt r0_term2 = offset_zz.MulMod(two_pows[i], order);
    r_poly.vec0[i] = r0_term1.AddMod(r0_term2, order);

    r_poly.vec1[i] = y_pows[i].MulMod(s_R_[i], order).MulMod(y_jn, order);
  }

  Poly2 t_poly = l_poly.InnerProduct(r_poly, curve);
  yacl::math::MPInt t_1_blinding = CreateRandomScalar(curve);
  yacl::math::MPInt t_2_blinding = CreateRandomScalar(curve);
  yacl::crypto::EcPoint T_1 = pc_gens_->Commit(t_poly.t1, t_1_blinding);
  yacl::crypto::EcPoint T_2 = pc_gens_->Commit(t_poly.t2, t_2_blinding);

  PolyCommitment poly_commitment{T_1, T_2};
  PartyAwaitingPolyChallenge next_state(
      std::move(v_blinding_), std::move(a_blinding_), std::move(s_blinding_),
      std::move(offset_zz), std::move(l_poly), std::move(r_poly),
      std::move(t_poly), std::move(t_1_blinding), std::move(t_2_blinding));

  return {std::move(next_state), poly_commitment};
}

PartyAwaitingPolyChallenge::PartyAwaitingPolyChallenge(
    yacl::math::MPInt v_blinding, yacl::math::MPInt a_blinding,
    yacl::math::MPInt s_blinding, yacl::math::MPInt offset_zz, VecPoly1 l_poly,
    VecPoly1 r_poly, Poly2 t_poly, yacl::math::MPInt t_1_blinding,
    yacl::math::MPInt t_2_blinding)
    : v_blinding_(std::move(v_blinding)),
      a_blinding_(std::move(a_blinding)),
      s_blinding_(std::move(s_blinding)),
      offset_zz_(std::move(offset_zz)),
      l_poly_(std::move(l_poly)),
      r_poly_(std::move(r_poly)),
      t_poly_(std::move(t_poly)),
      t_1_blinding_(std::move(t_1_blinding)),
      t_2_blinding_(std::move(t_2_blinding)) {}

Result<ProofShare> PartyAwaitingPolyChallenge::ApplyChallenge(
    const std::shared_ptr<yacl::crypto::EcGroup>& curve,
    const PolyChallenge& pc) {
  if (pc.x.IsZero()) {
    return Result<ProofShare>::Err(
        ProofError(ProofError::Code::MaliciousDealer));
  }
  const auto& order = curve->GetOrder();
  Poly2 t_blinding_poly(offset_zz_.MulMod(v_blinding_, order), t_1_blinding_,
                        t_2_blinding_);
  ProofShare share;
  share.t_x = t_poly_.Eval(pc.x, curve);
  share.t_x_blinding = t_blinding_poly.Eval(pc.x, curve);
  share.e_blinding = a_blinding_.AddMod(s_blinding_.MulMod(pc.x, order), order);
  share.l_vec = l_poly_.Eval(pc.x, curve);
  share.r_vec = r_poly_.Eval(pc.x, curve);
  return Result<ProofShare>::Ok(std::move(share));
}

// =============================================================================
// Dealer Implementation (Internal MPC logic)
// =============================================================================

Result<DealerAwaitingBitCommitments> Dealer::New(
    std::shared_ptr<const BulletproofGens> bp_gens,
    std::shared_ptr<const PedersenGens> pc_gens,
    std::shared_ptr<SimpleTranscript> transcript, size_t n, size_t m) {
  if (!(n == 8 || n == 16 || n == 32 || n == 64)) {
    return Result<DealerAwaitingBitCommitments>::Err(
        ProofError(ProofError::Code::InvalidBitsize));
  }
  size_t m_power_of_2 = NextPowerOfTwo(m);
  if (m == 0 || m != m_power_of_2) {
    return Result<DealerAwaitingBitCommitments>::Err(
        ProofError(ProofError::Code::InvalidAggregation));
  }
  if (bp_gens->gens_capacity() < n || bp_gens->party_capacity() < m) {
    return Result<DealerAwaitingBitCommitments>::Err(
        ProofError(ProofError::Code::InvalidGeneratorsLength));
  }
  transcript->RangeProofDomainSep(n, m);
  return Result<DealerAwaitingBitCommitments>::Ok(DealerAwaitingBitCommitments(
      n, m, std::move(transcript), std::move(bp_gens), std::move(pc_gens)));
}

DealerAwaitingBitCommitments::DealerAwaitingBitCommitments(
    size_t n, size_t m, std::shared_ptr<SimpleTranscript> transcript,
    std::shared_ptr<const BulletproofGens> bp_gens,
    std::shared_ptr<const PedersenGens> pc_gens)
    : n_(n),
      m_(m),
      transcript_(std::move(transcript)),
      bp_gens_(std::move(bp_gens)),
      pc_gens_(std::move(pc_gens)) {}

Result<std::pair<DealerAwaitingPolyCommitments, BitChallenge>>
DealerAwaitingBitCommitments::ReceiveBitCommitments(
    const std::shared_ptr<yacl::crypto::EcGroup>& curve,
    const std::vector<BitCommitment>& bit_commitments) {
  if (m_ != bit_commitments.size()) {
    return Result<std::pair<DealerAwaitingPolyCommitments, BitChallenge>>::Err(
        ProofError(ProofError::Code::WrongNumBitCommitments));
  }

  for (const auto& vc : bit_commitments) {
    transcript_->AppendPoint("V", vc.V_j, curve);
  }

  yacl::crypto::EcPoint A = curve->MulBase(yacl::math::MPInt(0));
  yacl::crypto::EcPoint S = curve->MulBase(yacl::math::MPInt(0));
  for (const auto& vc : bit_commitments) {
    A = curve->Add(A, vc.A_j);
    S = curve->Add(S, vc.S_j);
  }

  transcript_->AppendPoint("A", A, curve);
  transcript_->AppendPoint("S", S, curve);

  BitChallenge bit_challenge;
  bit_challenge.y = transcript_->ChallengeScalar("y", curve);
  bit_challenge.z = transcript_->ChallengeScalar("z", curve);

  DealerAwaitingPolyCommitments next_state(n_, m_, transcript_, bp_gens_,
                                           pc_gens_, bit_challenge,
                                           bit_commitments, A, S);
  return Result<std::pair<DealerAwaitingPolyCommitments, BitChallenge>>::Ok(
      {std::move(next_state), bit_challenge});
}

DealerAwaitingPolyCommitments::DealerAwaitingPolyCommitments(
    size_t n, size_t m, std::shared_ptr<SimpleTranscript> transcript,
    std::shared_ptr<const BulletproofGens> bp_gens,
    std::shared_ptr<const PedersenGens> pc_gens, BitChallenge bit_challenge,
    std::vector<BitCommitment> bit_commitments, yacl::crypto::EcPoint A,
    yacl::crypto::EcPoint S)
    : n_(n),
      m_(m),
      transcript_(std::move(transcript)),
      bp_gens_(std::move(bp_gens)),
      pc_gens_(std::move(pc_gens)),
      bit_challenge_(bit_challenge),
      bit_commitments_(std::move(bit_commitments)),
      A_(A),
      S_(S) {}

Result<std::pair<DealerAwaitingProofShares, PolyChallenge>>
DealerAwaitingPolyCommitments::ReceivePolyCommitments(
    const std::shared_ptr<yacl::crypto::EcGroup>& curve,
    const std::vector<PolyCommitment>& poly_commitments) {
  if (m_ != poly_commitments.size()) {
    return Result<std::pair<DealerAwaitingProofShares, PolyChallenge>>::Err(
        ProofError(ProofError::Code::WrongNumPolyCommitments));
  }

  yacl::crypto::EcPoint T_1 = curve->MulBase(yacl::math::MPInt(0));
  yacl::crypto::EcPoint T_2 = curve->MulBase(yacl::math::MPInt(0));
  for (const auto& pc : poly_commitments) {
    T_1 = curve->Add(T_1, pc.T_1_j);
    T_2 = curve->Add(T_2, pc.T_2_j);
  }

  transcript_->AppendPoint("T_1", T_1, curve);
  transcript_->AppendPoint("T_2", T_2, curve);

  PolyChallenge poly_challenge;
  poly_challenge.x = transcript_->ChallengeScalar("x", curve);

  DealerAwaitingProofShares next_state(
      n_, m_, transcript_, bp_gens_, pc_gens_, bit_challenge_,
      std::move(bit_commitments_), poly_challenge, poly_commitments, A_, S_,
      T_1, T_2);
  return Result<std::pair<DealerAwaitingProofShares, PolyChallenge>>::Ok(
      {std::move(next_state), poly_challenge});
}

DealerAwaitingProofShares::DealerAwaitingProofShares(
    size_t n, size_t m, std::shared_ptr<SimpleTranscript> transcript,
    std::shared_ptr<const BulletproofGens> bp_gens,
    std::shared_ptr<const PedersenGens> pc_gens, BitChallenge bit_challenge,
    std::vector<BitCommitment> bit_commitments, PolyChallenge poly_challenge,
    std::vector<PolyCommitment> poly_commitments, yacl::crypto::EcPoint A,
    yacl::crypto::EcPoint S, yacl::crypto::EcPoint T_1,
    yacl::crypto::EcPoint T_2)
    : n_(n),
      m_(m),
      transcript_(std::move(transcript)),
      bp_gens_(std::move(bp_gens)),
      pc_gens_(std::move(pc_gens)),
      bit_challenge_(bit_challenge),
      bit_commitments_(std::move(bit_commitments)),
      poly_challenge_(poly_challenge),
      poly_commitments_(std::move(poly_commitments)),
      A_(A),
      S_(S),
      T_1_(T_1),
      T_2_(T_2) {}

Result<RangeProof> DealerAwaitingProofShares::AssembleShares(
    const std::shared_ptr<yacl::crypto::EcGroup>& curve,
    const std::vector<ProofShare>& proof_shares) {
  if (m_ != proof_shares.size()) {
    return Result<RangeProof>::Err(
        ProofError(ProofError::Code::WrongNumProofShares));
  }

  const auto& order = curve->GetOrder();
  yacl::math::MPInt t_x(0), t_x_blinding(0), e_blinding(0);
  for (const auto& ps : proof_shares) {
    t_x = t_x.AddMod(ps.t_x, order);
    t_x_blinding = t_x_blinding.AddMod(ps.t_x_blinding, order);
    e_blinding = e_blinding.AddMod(ps.e_blinding, order);
  }

  transcript_->AppendScalar("t_x", t_x);
  transcript_->AppendScalar("t_x_blinding", t_x_blinding);
  transcript_->AppendScalar("e_blinding", e_blinding);

  yacl::math::MPInt w = transcript_->ChallengeScalar("w", curve);
  yacl::crypto::EcPoint Q = curve->Mul(pc_gens_->B, w);

  std::vector<yacl::math::MPInt> H_factors =
      ExpIterVector(bit_challenge_.y.InvertMod(order), n_ * m_, curve);

  std::vector<yacl::math::MPInt> l_vec, r_vec;
  l_vec.reserve(n_ * m_);
  r_vec.reserve(n_ * m_);
  for (const auto& ps : proof_shares) {
    l_vec.insert(l_vec.end(), ps.l_vec.begin(), ps.l_vec.end());
    r_vec.insert(r_vec.end(), ps.r_vec.begin(), ps.r_vec.end());
  }

  std::vector<yacl::math::MPInt> G_factors(
      n_ * m_, yacl::math::MPInt(1));  // G factors are 1s

  InnerProductProof ipp_proof = InnerProductProof::Create(
      *transcript_, curve, Q, G_factors, H_factors, bp_gens_->GetAllG(n_, m_),
      bp_gens_->GetAllH(n_, m_), std::move(l_vec), std::move(r_vec));

  return Result<RangeProof>::Ok(RangeProof(
      A_, S_, T_1_, T_2_, t_x, t_x_blinding, e_blinding, std::move(ipp_proof)));
}

// =============================================================================
// RangeProof Public Method Implementations
// =============================================================================

RangeProof::RangeProof(
    const yacl::crypto::EcPoint A, const yacl::crypto::EcPoint S,
    const yacl::crypto::EcPoint T_1, const yacl::crypto::EcPoint T_2,
    const yacl::math::MPInt t_x, const yacl::math::MPInt t_x_blinding,
    const yacl::math::MPInt e_blinding, InnerProductProof ipp_proof)
    : A_(std::move(A)),
      S_(std::move(S)),
      T_1_(std::move(T_1)),
      T_2_(std::move(T_2)),
      t_x_(std::move(t_x)),
      t_x_blinding_(std::move(t_x_blinding)),
      e_blinding_(std::move(e_blinding)),
      ipp_proof_(std::move(ipp_proof)) {}

yacl::math::MPInt RangeProof::Delta(
    size_t n, size_t m, const yacl::math::MPInt& y, const yacl::math::MPInt& z,
    const std::shared_ptr<yacl::crypto::EcGroup>& curve) {
  const auto& order = curve->GetOrder();
  yacl::math::MPInt two(2);
  yacl::math::MPInt zz = z.MulMod(z, order);

  yacl::math::MPInt sum_y = SumOfPowers(y, n * m, curve);
  yacl::math::MPInt sum_2 = SumOfPowers(two, n, curve);
  yacl::math::MPInt sum_z = SumOfPowers(z, m, curve);

  yacl::math::MPInt term1 = z.SubMod(zz, order).MulMod(sum_y, order);
  yacl::math::MPInt term2 =
      z.MulMod(zz, order).MulMod(sum_2, order).MulMod(sum_z, order);

  return term1.SubMod(term2, order);
}

Result<std::pair<RangeProof, yacl::crypto::EcPoint>> RangeProof::ProveSingle(
    std::shared_ptr<SimpleTranscript> transcript,
    const std::shared_ptr<yacl::crypto::EcGroup>& curve,
    const std::shared_ptr<const BulletproofGens>& bp_gens,
    const std::shared_ptr<const PedersenGens>& pc_gens, uint64_t v,
    const yacl::math::MPInt& v_blinding, size_t n) {
  auto result =
      ProveMultiple(transcript, curve, bp_gens, pc_gens, {v}, {v_blinding}, n);
  if (!result.IsOk()) {
    return Result<std::pair<RangeProof, yacl::crypto::EcPoint>>::Err(
        result.Error());
  }
  auto value = std::move(result).TakeValue();
  return Result<std::pair<RangeProof, yacl::crypto::EcPoint>>::Ok(
      {std::move(value.first), std::move(value.second[0])});
}

bool RangeProof::VerifySingle(
    std::shared_ptr<SimpleTranscript> transcript,
    const std::shared_ptr<yacl::crypto::EcGroup>& curve,
    const std::shared_ptr<const BulletproofGens>& bp_gens,
    const std::shared_ptr<const PedersenGens>& pc_gens,
    const yacl::crypto::EcPoint& V, size_t n) const {
  return VerifyMultiple(transcript, curve, bp_gens, pc_gens, {V}, n);
}

Result<std::pair<RangeProof, std::vector<yacl::crypto::EcPoint>>>
RangeProof::ProveMultiple(std::shared_ptr<SimpleTranscript> transcript,
                          const std::shared_ptr<yacl::crypto::EcGroup>& curve,
                          const std::shared_ptr<const BulletproofGens>& bp_gens,
                          const std::shared_ptr<const PedersenGens>& pc_gens,
                          const std::vector<uint64_t>& values,
                          const std::vector<yacl::math::MPInt>& blindings,
                          size_t n) {
  if (values.size() != blindings.size()) {
    return Result<std::pair<RangeProof, std::vector<yacl::crypto::EcPoint>>>::
        Err(ProofError(ProofError::Code::WrongNumBlindingFactors));
  }
  size_t m = values.size();

  auto dealer_res = Dealer::New(bp_gens, pc_gens, transcript, n, m);
  if (!dealer_res.IsOk()) {
    return Result<std::pair<RangeProof, std::vector<yacl::crypto::EcPoint>>>::
        Err(dealer_res.Error());
  }
  auto dealer1 = std::move(dealer_res).TakeValue();

  std::vector<PartyAwaitingPosition> parties;
  parties.reserve(m);
  for (size_t j = 0; j < m; ++j) {
    auto party_res = Party::New(bp_gens, pc_gens, values[j], blindings[j], n);
    if (!party_res.IsOk()) {
      return Result<std::pair<RangeProof, std::vector<yacl::crypto::EcPoint>>>::
          Err(party_res.Error());
    }
    parties.push_back(std::move(party_res).TakeValue());
  }

  std::vector<PartyAwaitingBitChallenge> parties2;
  std::vector<BitCommitment> bit_commitments;
  parties2.reserve(m);
  bit_commitments.reserve(m);
  for (size_t j = 0; j < m; ++j) {
    auto res = parties[j].AssignPosition(curve, j);
    if (!res.IsOk()) {
      return Result<std::pair<RangeProof, std::vector<yacl::crypto::EcPoint>>>::
          Err(res.Error());
    }
    auto value = std::move(res).TakeValue();
    parties2.push_back(std::move(value.first));
    bit_commitments.push_back(value.second);
  }

  std::vector<yacl::crypto::EcPoint> value_commitments;
  value_commitments.reserve(m);
  for (const auto& bc : bit_commitments) {
    value_commitments.push_back(bc.V_j);
  }

  auto dealer2_res = dealer1.ReceiveBitCommitments(curve, bit_commitments);
  if (!dealer2_res.IsOk()) {
    return Result<std::pair<RangeProof, std::vector<yacl::crypto::EcPoint>>>::
        Err(dealer2_res.Error());
  }
  auto dealer2_pair = std::move(dealer2_res).TakeValue();
  auto dealer2 = std::move(dealer2_pair.first);
  auto bit_challenge = dealer2_pair.second;

  std::vector<PartyAwaitingPolyChallenge> parties3;
  std::vector<PolyCommitment> poly_commitments;
  parties3.reserve(m);
  poly_commitments.reserve(m);
  for (size_t j = 0; j < m; ++j) {
    auto pair = parties2[j].ApplyChallenge(curve, bit_challenge);
    parties3.push_back(std::move(pair.first));
    poly_commitments.push_back(pair.second);
  }

  auto dealer3_res = dealer2.ReceivePolyCommitments(curve, poly_commitments);
  if (!dealer3_res.IsOk()) {
    return Result<std::pair<RangeProof, std::vector<yacl::crypto::EcPoint>>>::
        Err(dealer3_res.Error());
  }
  auto dealer3_pair = std::move(dealer3_res).TakeValue();
  auto dealer3 = std::move(dealer3_pair.first);
  auto poly_challenge = dealer3_pair.second;

  std::vector<ProofShare> proof_shares;
  proof_shares.reserve(m);
  for (size_t j = 0; j < m; ++j) {
    auto share_res = parties3[j].ApplyChallenge(curve, poly_challenge);
    if (!share_res.IsOk()) {
      return Result<std::pair<RangeProof, std::vector<yacl::crypto::EcPoint>>>::
          Err(share_res.Error());
    }
    proof_shares.push_back(std::move(share_res).TakeValue());
  }

  auto proof_res = dealer3.AssembleShares(curve, proof_shares);
  if (!proof_res.IsOk()) {
    return Result<std::pair<RangeProof, std::vector<yacl::crypto::EcPoint>>>::
        Err(proof_res.Error());
  }

  return Result<std::pair<RangeProof, std::vector<yacl::crypto::EcPoint>>>::Ok(
      {std::move(proof_res).TakeValue(), std::move(value_commitments)});
}

bool RangeProof::VerifyMultiple(
    std::shared_ptr<SimpleTranscript> transcript,
    const std::shared_ptr<yacl::crypto::EcGroup>& curve,
    const std::shared_ptr<const BulletproofGens>& bp_gens,
    const std::shared_ptr<const PedersenGens>& pc_gens,
    const std::vector<yacl::crypto::EcPoint>& value_commitments,
    size_t n) const {
  const size_t m = value_commitments.size();
  const auto& order = curve->GetOrder();

  if (!(n == 8 || n == 16 || n == 32 || n == 64)) return false;
  if (bp_gens->gens_capacity() < n) return false;
  if (bp_gens->party_capacity() < m) return false;

  transcript->RangeProofDomainSep(n, m);

  for (const auto& V : value_commitments) {
    transcript->AppendPoint("V", V, curve);
  }

  transcript->ValidateAndAppendPoint("A", A_, curve);
  transcript->ValidateAndAppendPoint("S", S_, curve);

  yacl::math::MPInt y = transcript->ChallengeScalar("y", curve);
  yacl::math::MPInt z = transcript->ChallengeScalar("z", curve);

  transcript->ValidateAndAppendPoint("T_1", T_1_, curve);
  transcript->ValidateAndAppendPoint("T_2", T_2_, curve);

  yacl::math::MPInt x = transcript->ChallengeScalar("x", curve);

  transcript->AppendScalar("t_x", t_x_);
  transcript->AppendScalar("t_x_blinding", t_x_blinding_);
  transcript->AppendScalar("e_blinding", e_blinding_);

  yacl::math::MPInt w = transcript->ChallengeScalar("w", curve);

  auto verification_scalars =
      ipp_proof_.VerificationScalars(n * m, *transcript, curve);
  const auto& x_sq = std::get<0>(verification_scalars);
  const auto& x_inv_sq = std::get<1>(verification_scalars);
  const auto& s = std::get<2>(verification_scalars);

  auto s_inv = s;
  std::reverse(s_inv.begin(), s_inv.end());
  const auto& a = ipp_proof_.GetA();
  const auto& b = ipp_proof_.GetB();

  auto powers_of_2 = ExpIterVector(yacl::math::MPInt(2), n, curve);
  auto powers_of_z = ExpIterVector(z, m, curve);

  std::vector<yacl::math::MPInt> concat_z_and_2;
  concat_z_and_2.reserve(n * m);
  for (const auto& exp_z : powers_of_z) {
    for (const auto& exp_2 : powers_of_2) {
      concat_z_and_2.push_back(exp_z.MulMod(exp_2, order));
    }
  }

  yacl::math::MPInt y_inv = y.InvertMod(order);
  auto y_inv_pows = ExpIterVector(y_inv, n * m, curve);
  yacl::math::MPInt zz = z.MulMod(z, order);

  yacl::math::MPInt minus_z = yacl::math::MPInt(0).SubMod(z, order);

  std::vector<yacl::math::MPInt> g_scalars;
  g_scalars.reserve(n * m);
  for (const auto& s_i : s) {
    g_scalars.push_back(minus_z.SubMod(a.MulMod(s_i, order), order));
  }

  std::vector<yacl::math::MPInt> h_scalars;
  h_scalars.reserve(n * m);
  for (size_t i = 0; i < n * m; ++i) {
    yacl::math::MPInt term = zz.MulMod(concat_z_and_2[i], order)
                                 .SubMod(b.MulMod(s_inv[i], order), order);
    h_scalars.push_back(z.AddMod(y_inv_pows[i].MulMod(term, order), order));
  }

  yacl::math::MPInt value_commitment_scalar = w.MulMod(zz, order);
  std::vector<yacl::math::MPInt> vc_scalars;
  for (const auto& p_z : powers_of_z) {
    vc_scalars.push_back(value_commitment_scalar.MulMod(p_z, order));
  }

  yacl::math::MPInt delta_val = Delta(n, m, y, z, curve);
  yacl::math::MPInt basepoint_scalar =
      w.MulMod(t_x_.SubMod(a.MulMod(b, order), order), order);
  basepoint_scalar = basepoint_scalar.AddMod(
      w.MulMod(delta_val.SubMod(t_x_, order), order), order);

  std::vector<yacl::math::MPInt> msm_scalars;
  msm_scalars.push_back(yacl::math::MPInt(1));
  msm_scalars.push_back(x);
  msm_scalars.push_back(w.MulMod(x, order));
  msm_scalars.push_back(w.MulMod(x.MulMod(x, order), order));
  msm_scalars.insert(msm_scalars.end(), x_sq.begin(), x_sq.end());
  msm_scalars.insert(msm_scalars.end(), x_inv_sq.begin(), x_inv_sq.end());

  yacl::math::MPInt blinding_term =
      e_blinding_.AddMod(w.MulMod(t_x_blinding_, order), order);
  msm_scalars.push_back(yacl::math::MPInt(0).SubMod(blinding_term, order));

  msm_scalars.push_back(basepoint_scalar);
  msm_scalars.insert(msm_scalars.end(), g_scalars.begin(), g_scalars.end());
  msm_scalars.insert(msm_scalars.end(), h_scalars.begin(), h_scalars.end());
  msm_scalars.insert(msm_scalars.end(), vc_scalars.begin(), vc_scalars.end());

  std::vector<yacl::crypto::EcPoint> msm_points;
  msm_points.push_back(A_);
  msm_points.push_back(S_);
  msm_points.push_back(T_1_);
  msm_points.push_back(T_2_);
  auto L_vec = ipp_proof_.GetLVec();
  auto R_vec = ipp_proof_.GetRVec();
  msm_points.insert(msm_points.end(), L_vec.begin(), L_vec.end());
  msm_points.insert(msm_points.end(), R_vec.begin(), R_vec.end());
  msm_points.push_back(pc_gens->B_blinding);
  msm_points.push_back(pc_gens->B);
  auto G_all = bp_gens->GetAllG(n, m);
  auto H_all = bp_gens->GetAllH(n, m);
  msm_points.insert(msm_points.end(), G_all.begin(), G_all.end());
  msm_points.insert(msm_points.end(), H_all.begin(), H_all.end());
  msm_points.insert(msm_points.end(), value_commitments.begin(),
                    value_commitments.end());

  yacl::crypto::EcPoint mega_check =
      MultiScalarMul(curve, msm_scalars, msm_points);

  return curve->IsInfinity(mega_check);
}

yacl::Buffer RangeProof::ToBytes(
    const std::shared_ptr<yacl::crypto::EcGroup>& curve) const {
  size_t point_size = curve->GetSerializeLength();
  yacl::Buffer A_bytes = curve->SerializePoint(A_);
  yacl::Buffer S_bytes = curve->SerializePoint(S_);
  yacl::Buffer T1_bytes = curve->SerializePoint(T_1_);
  yacl::Buffer T2_bytes = curve->SerializePoint(T_2_);

  std::vector<uint8_t> t_x_bytes(32);
  t_x_.ToMagBytes(t_x_bytes.data(), t_x_bytes.size(), yacl::Endian::little);

  std::vector<uint8_t> t_x_blinding_bytes(32);
  t_x_blinding_.ToMagBytes(t_x_blinding_bytes.data(), t_x_blinding_bytes.size(),
                           yacl::Endian::little);

  std::vector<uint8_t> e_blinding_bytes(32);
  e_blinding_.ToMagBytes(e_blinding_bytes.data(), e_blinding_bytes.size(),
                         yacl::Endian::little);

  yacl::Buffer ipp_bytes = ipp_proof_.ToBytes(curve);

  size_t total_size = 4 * point_size + 3 * 32 + ipp_bytes.size();
  yacl::Buffer buf(total_size);
  char* ptr = buf.data<char>();

  auto write_data = [&](const yacl::Buffer& data) {
    std::memcpy(ptr, data.data(), data.size());
    ptr += data.size();
  };

  auto write_vec = [&](const std::vector<uint8_t>& data) {
    std::memcpy(ptr, data.data(), data.size());
    ptr += data.size();
  };

  write_data(A_bytes);
  write_data(S_bytes);
  write_data(T1_bytes);
  write_data(T2_bytes);

  write_vec(t_x_bytes);
  write_vec(t_x_blinding_bytes);
  write_vec(e_blinding_bytes);

  write_data(ipp_bytes);

  YACL_ENFORCE(ptr == buf.data<char>() + total_size,
               "Serialization size mismatch");

  return buf;
}

RangeProof RangeProof::FromBytes(
    const std::shared_ptr<yacl::crypto::EcGroup>& curve,
    const yacl::ByteContainerView& bytes) {
  size_t point_size = curve->GetSerializeLength();
  size_t min_size = 4 * point_size + 3 * 32;
  YACL_ENFORCE(bytes.size() >= min_size, "Invalid proof format: too short");

  size_t offset = 0;
  auto read_point = [&](size_t& offset) {
    yacl::crypto::EcPoint p =
        curve->DeserializePoint(bytes.subspan(offset, point_size));
    offset += point_size;
    return p;
  };
  auto read_scalar = [&](size_t& offset) {
    yacl::math::MPInt s;
    s.FromMagBytes(bytes.subspan(offset, 32), yacl::Endian::little);
    offset += 32;
    return s;
  };

  yacl::crypto::EcPoint A = read_point(offset);
  yacl::crypto::EcPoint S = read_point(offset);
  yacl::crypto::EcPoint T_1 = read_point(offset);
  yacl::crypto::EcPoint T_2 = read_point(offset);

  yacl::math::MPInt t_x = read_scalar(offset);
  yacl::math::MPInt t_x_blinding = read_scalar(offset);
  yacl::math::MPInt e_blinding = read_scalar(offset);

  InnerProductProof ipp_proof = InnerProductProof::FromBytes(
      bytes.subspan(offset, bytes.size() - offset), curve);

  return RangeProof(std::move(A), std::move(S), std::move(T_1), std::move(T_2),
                    std::move(t_x), std::move(t_x_blinding),
                    std::move(e_blinding), std::move(ipp_proof));
}

}  // namespace examples::zkp