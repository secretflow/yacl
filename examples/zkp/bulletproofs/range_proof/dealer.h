#pragma once

#include <cstdint>
#include <memory>
#include <vector>

#include "yacl/base/exception.h"
#include "yacl/crypto/ecc/ec_point.h"
#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/math/mpint/mp_int.h"
#include "zkp/bulletproofs/generators.h"
#include "zkp/bulletproofs/range_proof/messages.h"
#include "zkp/bulletproofs/range_proof/range_proof.h"
#include "zkp/bulletproofs/transcript.h"

namespace examples::zkp {

// Forward declarations
class DealerAwaitingBitCommitments;
class DealerAwaitingPolyCommitments;
class DealerAwaitingProofShares;

/**
 * @brief Used to construct a dealer for the aggregated rangeproof MPC protocol.
 */
class Dealer {
 public:
  /**
   * @brief Creates a new dealer coordinating m parties proving n-bit ranges.
   * 
   * @param bp_gens Bulletproof generators
   * @param pc_gens Pedersen generators
   * @param transcript Transcript for the protocol
   * @param n Bitsize of the range proof (must be 8, 16, 32, or 64)
   * @param m Number of parties (must be a power of 2)
   * @return DealerAwaitingBitCommitments Initial dealer state
   * @throws yacl::Exception if parameters are invalid
   */
  static DealerAwaitingBitCommitments New(
      const BulletproofGens& bp_gens,
      const PedersenGens& pc_gens,
      Transcript& transcript,
      size_t n,
      size_t m);
};

/**
 * @brief A dealer waiting for the parties to send their BitCommitments.
 */
class DealerAwaitingBitCommitments {
 public:
  /**
   * @brief Receive each party's BitCommitments and compute the BitChallenge.
   * 
   * @param bit_commitments Vector of bit commitments from all parties
   * @return std::pair<DealerAwaitingPolyCommitments, BitChallenge> Next state and challenge
   * @throws yacl::Exception if wrong number of commitments received
   */
  std::pair<DealerAwaitingPolyCommitments, BitChallenge> ReceiveBitCommitments(
      const std::vector<BitCommitment>& bit_commitments);

  // Deleted copy constructor and assignment to prevent copies
  DealerAwaitingBitCommitments(const DealerAwaitingBitCommitments&) = delete;
  DealerAwaitingBitCommitments& operator=(const DealerAwaitingBitCommitments&) = delete;
  
  // Allow move operations
  DealerAwaitingBitCommitments(DealerAwaitingBitCommitments&&) = default;
  DealerAwaitingBitCommitments& operator=(DealerAwaitingBitCommitments&&) = default;

 private:
  friend class Dealer;

  DealerAwaitingBitCommitments(
      const BulletproofGens& bp_gens,
      const PedersenGens& pc_gens,
      Transcript& transcript,
      Transcript initial_transcript,
      size_t n,
      size_t m);

  const BulletproofGens& bp_gens_;
  const PedersenGens& pc_gens_;
  Transcript& transcript_;
  // The dealer keeps a copy of the initial transcript state for verification
  Transcript initial_transcript_;
  size_t n_; // Bitsize of the range
  size_t m_; // Number of parties
};

/**
 * @brief A dealer which has sent the BitChallenge to the parties and
 * is waiting for their PolyCommitments.
 */
class DealerAwaitingPolyCommitments {
 public:
  /**
   * @brief Receive PolyCommitments from the parties and compute the PolyChallenge.
   * 
   * @param poly_commitments Vector of polynomial commitments from all parties
   * @return std::pair<DealerAwaitingProofShares, PolyChallenge> Next state and challenge
   * @throws yacl::Exception if wrong number of commitments received
   */
  std::pair<DealerAwaitingProofShares, PolyChallenge> ReceivePolyCommitments(
      const std::vector<PolyCommitment>& poly_commitments);

  // Deleted copy constructor and assignment to prevent copies
  DealerAwaitingPolyCommitments(const DealerAwaitingPolyCommitments&) = delete;
  DealerAwaitingPolyCommitments& operator=(const DealerAwaitingPolyCommitments&) = delete;
  
  // Allow move operations
  DealerAwaitingPolyCommitments(DealerAwaitingPolyCommitments&&) = default;
  DealerAwaitingPolyCommitments& operator=(DealerAwaitingPolyCommitments&&) = default;

 private:
  friend class DealerAwaitingBitCommitments;

  DealerAwaitingPolyCommitments(
      size_t n,
      size_t m,
      Transcript& transcript,
      Transcript initial_transcript,
      const BulletproofGens& bp_gens,
      const PedersenGens& pc_gens,
      const BitChallenge& bit_challenge,
      std::vector<BitCommitment> bit_commitments,
      const yacl::crypto::EcPoint& A,
      const yacl::crypto::EcPoint& S);

  size_t n_; // Bitsize of the range
  size_t m_; // Number of parties
  Transcript& transcript_;
  Transcript initial_transcript_;
  const BulletproofGens& bp_gens_;
  const PedersenGens& pc_gens_;
  BitChallenge bit_challenge_;
  std::vector<BitCommitment> bit_commitments_;
  yacl::crypto::EcPoint A_; // Aggregated commitment to the parties' bits
  yacl::crypto::EcPoint S_; // Aggregated commitment to the parties' bit blindings
};

/**
 * @brief A dealer which has sent the PolyChallenge to the parties and
 * is waiting to aggregate their ProofShares into a RangeProof.
 */
class DealerAwaitingProofShares {
 public:
  /**
   * @brief Assemble the final aggregated RangeProof from the given proof_shares,
   * then validate the proof to ensure that all ProofShares were well-formed.
   * 
   * @param proof_shares Vector of proof shares from all parties
   * @return RangeProof Aggregated range proof
   * @throws yacl::Exception if any proof shares are malformed
   */
  RangeProof ReceiveShares(const std::vector<ProofShare>& proof_shares);

  /**
   * @brief Assemble the final aggregated RangeProof from the given proof_shares,
   * but skip validation of the proof.
   * 
   * @param proof_shares Vector of proof shares from all parties
   * @return RangeProof Aggregated range proof
   * @throws yacl::Exception if wrong number of shares received
   * 
   * @warning This function does NOT validate the proof shares. It is suitable
   * only when all parties are known to be honest.
   */
  RangeProof ReceiveTrustedShares(const std::vector<ProofShare>& proof_shares);

  // Deleted copy constructor and assignment to prevent copies
  DealerAwaitingProofShares(const DealerAwaitingProofShares&) = delete;
  DealerAwaitingProofShares& operator=(const DealerAwaitingProofShares&) = delete;
  
  // Allow move operations
  DealerAwaitingProofShares(DealerAwaitingProofShares&&) = default;
  DealerAwaitingProofShares& operator=(DealerAwaitingProofShares&&) = default;

 private:
  friend class DealerAwaitingPolyCommitments;

  DealerAwaitingProofShares(
      size_t n,
      size_t m,
      Transcript& transcript,
      Transcript initial_transcript,
      const BulletproofGens& bp_gens,
      const PedersenGens& pc_gens,
      const BitChallenge& bit_challenge,
      std::vector<BitCommitment> bit_commitments,
      const PolyChallenge& poly_challenge,
      std::vector<PolyCommitment> poly_commitments,
      const yacl::crypto::EcPoint& A,
      const yacl::crypto::EcPoint& S,
      const yacl::crypto::EcPoint& T_1,
      const yacl::crypto::EcPoint& T_2);

  /**
   * @brief Helper function to assemble proof shares into a RangeProof.
   * 
   * @param proof_shares Vector of proof shares from all parties
   * @return RangeProof Aggregated range proof
   * @throws yacl::Exception if any proof shares are malformed
   */
  RangeProof AssembleShares(const std::vector<ProofShare>& proof_shares);

  size_t n_; // Bitsize of the range
  size_t m_; // Number of parties
  Transcript& transcript_;
  Transcript initial_transcript_;
  const BulletproofGens& bp_gens_;
  const PedersenGens& pc_gens_;
  BitChallenge bit_challenge_;
  std::vector<BitCommitment> bit_commitments_;
  PolyChallenge poly_challenge_;
  std::vector<PolyCommitment> poly_commitments_;
  yacl::crypto::EcPoint A_;
  yacl::crypto::EcPoint S_;
  yacl::crypto::EcPoint T_1_;
  yacl::crypto::EcPoint T_2_;
};

/**
 * @brief Check if a number is a power of 2
 */
inline bool IsPowerOfTwo(size_t n) {
  return n > 0 && (n & (n - 1)) == 0;
}

} // namespace examples::zkp