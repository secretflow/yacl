#include "zkp/bulletproofs/range_proof_mpc/dealer.h"

#include <algorithm>
#include <numeric>
#include <stdexcept>

#include "yacl/crypto/hash/hash_utils.h"
#include "yacl/math/mpint/mp_int.h"
#include "zkp/bulletproofs/ipa/inner_product_proof.h"
#include "zkp/bulletproofs/util.h"
#include "zkp/bulletproofs/range_proof_mpc/range_proof_mpc.h"
namespace examples::zkp {

//-------------------- Dealer --------------------

DealerAwaitingBitCommitments Dealer::New(
    const BulletproofGens& bp_gens,
    const PedersenGens& pc_gens,
    SimpleTranscript& transcript,
    size_t n,
    size_t m) {
  // Check that n is a valid bitsize
  if (!(n == 8 || n == 16 || n == 32 || n == 64)) {
    throw yacl::Exception("Invalid bitsize, must be 8, 16, 32, or 64");
  }
  
  // Check that m is a power of 2
  if (!IsPowerOfTwo(m)) {
    throw yacl::Exception("Number of parties must be a power of 2");
  }
  
  // Check that generators are sufficient
  if (bp_gens.gens_capacity() < n) {
    throw yacl::Exception("Generators capacity is insufficient for the bitsize");
  }
  
  if (bp_gens.party_capacity() < m) {
    throw yacl::Exception("Generators capacity is insufficient for the number of parties");
  }
  
  // Keep a copy of the initial transcript state for verification
  SimpleTranscript initial_transcript = transcript;
  
  // Set domain separator for the range proof
  transcript.RangeProofDomainSep(n, m);
  
  return DealerAwaitingBitCommitments(
      bp_gens, pc_gens, transcript, initial_transcript, n, m);
}

//-------------------- DealerAwaitingBitCommitments --------------------

DealerAwaitingBitCommitments::DealerAwaitingBitCommitments(
    const BulletproofGens& bp_gens,
    const PedersenGens& pc_gens,
    SimpleTranscript& transcript,
    SimpleTranscript initial_transcript,
    size_t n,
    size_t m)
    : bp_gens_(bp_gens),
      pc_gens_(pc_gens),
      transcript_(transcript),
      initial_transcript_(std::move(initial_transcript)),
      n_(n),
      m_(m) {}

std::pair<DealerAwaitingPolyCommitments, BitChallenge>
DealerAwaitingBitCommitments::ReceiveBitCommitments(
    const std::vector<BitCommitment>& bit_commitments) {
  if (m_ != bit_commitments.size()) {
    throw yacl::Exception("Wrong number of bit commitments");
  }
  
  auto curve = bp_gens_.GetCurve();
  
  // Commit each V_j individually
  for (const auto& commitment : bit_commitments) {
    transcript_.AppendPoint("V", commitment.GetV(), curve);
  }
  
  // Compute aggregated A_j and S_j
  yacl::crypto::EcPoint A = curve->GetGenerator();
  curve->MulInplace(&A, yacl::math::MPInt(0)); // Set to identity/infinity
  yacl::crypto::EcPoint S = curve->GetGenerator();
  curve->MulInplace(&S, yacl::math::MPInt(0)); // Set to identity/infinity
  
  for (const auto& commitment : bit_commitments) {
    A = curve->Add(A, commitment.GetA());
    S = curve->Add(S, commitment.GetS());
  }
  
  // Commit aggregated A and S
  transcript_.AppendPoint("A", A, curve);
  transcript_.AppendPoint("S", S, curve);
  
  // Generate challenges
  yacl::math::MPInt y = transcript_.ChallengeScalar("y", curve);
  yacl::math::MPInt z = transcript_.ChallengeScalar("z", curve);
  
  BitChallenge bit_challenge(y, z);
  
  
  // Return next state and the challenge
  return {
      DealerAwaitingPolyCommitments(
          n_, 
          m_, 
          transcript_, 
          initial_transcript_,
          bp_gens_, 
          pc_gens_, 
          bit_challenge,
          bit_commitments,
          A, 
          S
      ),
      bit_challenge
  };
}

//-------------------- DealerAwaitingPolyCommitments --------------------

std::pair<DealerAwaitingProofShares, PolyChallenge>
DealerAwaitingPolyCommitments::ReceivePolyCommitments(
    const std::vector<PolyCommitment>& poly_commitments) {
  if (m_ != poly_commitments.size()) {
    throw yacl::Exception("Wrong number of polynomial commitments");
  }
  
  auto curve = bp_gens_.GetCurve();
  
  // Compute sums of T_1_j's and T_2_j's
  yacl::crypto::EcPoint T_1 = curve->GetGenerator();
  curve->MulInplace(&T_1, yacl::math::MPInt(0)); // Set to identity/infinity
  yacl::crypto::EcPoint T_2 = curve->GetGenerator();
  curve->MulInplace(&T_2, yacl::math::MPInt(0)); // Set to identity/infinity
  
  for (const auto& commitment : poly_commitments) {
    T_1 = curve->Add(T_1, commitment.GetT1());
    T_2 = curve->Add(T_2, commitment.GetT2());
  }
  
  // Commit aggregated T_1 and T_2
  transcript_.AppendPoint("T_1", T_1, curve);
  transcript_.AppendPoint("T_2", T_2, curve);
  
  // Generate challenge
  yacl::math::MPInt x = transcript_.ChallengeScalar("x", curve);
  
  PolyChallenge poly_challenge(x);
  
  // Create poly commitments copy for the next state
  std::vector<PolyCommitment> poly_commitments_copy(poly_commitments.begin(), poly_commitments.end());
  
  // Return next state and the challenge
  return {
      DealerAwaitingProofShares(
          n_, m_, transcript_, initial_transcript_,
          bp_gens_, pc_gens_, bit_challenge_,
          std::move(bit_commitments_), poly_challenge,
          std::move(poly_commitments_copy), A_, S_, T_1, T_2),
      poly_challenge
  };
}

//-------------------- DealerAwaitingProofShares --------------------



RangeProofMPC DealerAwaitingProofShares::AssembleShares(
    const std::vector<ProofShare>& proof_shares) {
  if (m_ != proof_shares.size()) {
    throw yacl::Exception("Wrong number of proof shares");
  }
  
  // Validate lengths for each share
  std::vector<size_t> bad_shares;
  for (size_t j = 0; j < proof_shares.size(); j++) {
    try {
      proof_shares[j].CheckSize(n_, bp_gens_, j);
    } catch (const std::exception&) {
      bad_shares.push_back(j);
    }
  }
  
  if (!bad_shares.empty()) {
    throw yacl::Exception("Malformed proof shares detected");
  }
  
  // Combine the proof shares
  auto curve = bp_gens_.GetCurve();
  auto order = curve->GetOrder();
  
  // Aggregate t_x, t_x_blinding, and e_blinding values
  yacl::math::MPInt t_x(0);
  yacl::math::MPInt t_x_blinding(0);
  yacl::math::MPInt e_blinding(0);
  
  for (const auto& share : proof_shares) {
    t_x = t_x.AddMod(share.GetTX(), order);
    t_x_blinding = t_x_blinding.AddMod(share.GetTXBlinding(), order);
    e_blinding = e_blinding.AddMod(share.GetEBlinding(), order);
  }
  
  // Add these values to the transcript
  transcript_.AppendScalar("t_x", t_x);
  transcript_.AppendScalar("t_x_blinding", t_x_blinding);
  transcript_.AppendScalar("e_blinding", e_blinding);
  
  // Get a challenge value to combine statements for the IPP
  yacl::math::MPInt w = transcript_.ChallengeScalar("w", curve);
  yacl::crypto::EcPoint Q = curve->Mul(pc_gens_.B, w);
  
  // Prepare G_factors and H_factors for the inner product proof
  std::vector<yacl::math::MPInt> G_factors(n_ * m_, yacl::math::MPInt(1));
  
  yacl::math::MPInt y_inv = bit_challenge_.GetY().InvertMod(order);
  std::vector<yacl::math::MPInt> H_factors = ExpIterVector(y_inv, n_ * m_, curve);
  
  // Collect l_vec and r_vec from all proof shares
  std::vector<yacl::math::MPInt> l_vec;
  std::vector<yacl::math::MPInt> r_vec;
  l_vec.reserve(n_ * m_);
  r_vec.reserve(n_ * m_);
  
  for (const auto& share : proof_shares) {
    const auto& share_l_vec = share.GetLVec();
    const auto& share_r_vec = share.GetRVec();
    
    l_vec.insert(l_vec.end(), share_l_vec.begin(), share_l_vec.end());
    r_vec.insert(r_vec.end(), share_r_vec.begin(), share_r_vec.end());
  }
  
  // Collect G and H generators
  std::vector<yacl::crypto::EcPoint> G_vec = bp_gens_.GetAllG(n_, m_);
  std::vector<yacl::crypto::EcPoint> H_vec = bp_gens_.GetAllH(n_, m_);
  
  // Create inner product proof
  InnerProductProof ipp_proof = InnerProductProof::Create(
    &transcript_, curve, Q, G_factors, H_factors, G_vec, H_vec, l_vec, r_vec);
  
  // Construct the range proof
  return RangeProofMPC(A_, S_, T_1_, T_2_, t_x, t_x_blinding, e_blinding, ipp_proof);
}

RangeProofMPC DealerAwaitingProofShares::ReceiveShares(
    const std::vector<ProofShare>& proof_shares) {
  RangeProofMPC proof = AssembleShares(proof_shares);
  
  // Extract value commitments from bit commitments
  std::vector<yacl::crypto::EcPoint> Vs;
  Vs.reserve(bit_commitments_.size());
  
  for (const auto& commitment : bit_commitments_) {
    Vs.push_back(commitment.GetV());
  }
  
  // Verify the proof using the initial transcript
  SimpleTranscript verification_transcript = initial_transcript_;
  
  try {
    proof.VerifyMultiple(bp_gens_, pc_gens_, verification_transcript, Vs, n_);
  } catch (const std::exception&) {
    // Proof verification failed. Now audit the parties
    std::vector<size_t> bad_shares;
    
    for (size_t j = 0; j < m_; j++) {
      try {
        proof_shares[j].AuditShare(
            bp_gens_, pc_gens_, j,
            bit_commitments_[j], bit_challenge_,
            poly_commitments_[j], poly_challenge_);
      } catch (const std::exception&) {
        bad_shares.push_back(j);
      }
    }
    
    throw yacl::Exception("Malformed proof shares detected during verification");
  }
  
  return proof;
}

RangeProofMPC DealerAwaitingProofShares::ReceiveTrustedShares(
    const std::vector<ProofShare>& proof_shares) {
  // Skip verification since shares are trusted
  return AssembleShares(proof_shares);
}

} // namespace examples::zkp