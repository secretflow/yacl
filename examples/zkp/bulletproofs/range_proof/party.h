#pragma once

#include <cstdint>
#include <memory>
#include <vector>

#include "yacl/base/exception.h"
#include "yacl/crypto/ecc/ec_point.h"
#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/math/mpint/mp_int.h"
#include "zkp/bulletproofs/generators.h"
#include "zkp/bulletproofs/range_proof/messagess.h"
#include "zkp/bulletproofs/util.h"

namespace examples::zkp {

// Forward declarations
class PartyAwaitingPosition;
class PartyAwaitingBitChallenge;
class PartyAwaitingPolyChallenge;

// Error codes for multi-party computation
enum class MPCError {
  kOk = 0,
  kInvalidBitsize,
  kInvalidGeneratorsLength,
  kMaliciousDealer,
};

/**
 * @brief Used to construct a party for the aggregated rangeproof MPC protocol.
 */
class Party {
 public:
  /**
   * @brief Constructs a PartyAwaitingPosition with the given rangeproof parameters.
   * 
   * @param bp_gens Bulletproof generators
   * @param pc_gens Pedersen generators
   * @param v Value to prove is in range
   * @param v_blinding Blinding factor for the value commitment
   * @param n Bitsize of the range (must be 8, 16, 32, or 64)
   * @return PartyAwaitingPosition The initial party state
   * @throws yacl::Exception if parameters are invalid
   */
  static PartyAwaitingPosition New(
      const BulletproofGens& bp_gens,
      const PedersenGens& pc_gens,
      uint64_t v,
      const yacl::math::MPInt& v_blinding,
      size_t n);
};

/**
 * @brief A party waiting for the dealer to assign their position in the aggregation.
 */
class PartyAwaitingPosition {
 public:
  /**
   * @brief Assigns a position in the aggregated proof to this party.
   * 
   * @param j Position in the aggregation
   * @return std::pair<PartyAwaitingBitChallenge, BitCommitment> Next state and commitments
   * @throws yacl::Exception if position is invalid
   */
  std::pair<PartyAwaitingBitChallenge, BitCommitment> AssignPosition(size_t j) const;

  // Deleted copy constructor and assignment to prevent copies
  PartyAwaitingPosition(const PartyAwaitingPosition&) = delete;
  PartyAwaitingPosition& operator=(const PartyAwaitingPosition&) = delete;
  
  // Allow move operations
  PartyAwaitingPosition(PartyAwaitingPosition&&) = default;
  PartyAwaitingPosition& operator=(PartyAwaitingPosition&&) = default;

  ~PartyAwaitingPosition();

 private:
  friend class Party;

  PartyAwaitingPosition(
      const BulletproofGens& bp_gens,
      const PedersenGens& pc_gens,
      uint64_t v,
      const yacl::math::MPInt& v_blinding,
      size_t n);

  const BulletproofGens& bp_gens_;
  const PedersenGens& pc_gens_;
  size_t n_;
  uint64_t v_;
  yacl::math::MPInt v_blinding_;
  yacl::crypto::EcPoint V_;  // Commitment to value
};

/**
 * @brief A party which has committed to the bits of its value
 * and is waiting for the aggregated value challenge from the dealer.
 */
class PartyAwaitingBitChallenge {
 public:
  /**
   * @brief Apply a bit challenge from the dealer to compute commitments to polynomial coefficients.
   * 
   * @param challenge The challenge from the dealer
   * @return std::pair<PartyAwaitingPolyChallenge, PolyCommitment> Next state and commitments
   */
  std::pair<PartyAwaitingPolyChallenge, PolyCommitment> ApplyChallenge(
      const BitChallenge& challenge) const;

  // Deleted copy constructor and assignment to prevent copies
  PartyAwaitingBitChallenge(const PartyAwaitingBitChallenge&) = delete;
  PartyAwaitingBitChallenge& operator=(const PartyAwaitingBitChallenge&) = delete;
  
  // Allow move operations
  PartyAwaitingBitChallenge(PartyAwaitingBitChallenge&&) = default;
  PartyAwaitingBitChallenge& operator=(PartyAwaitingBitChallenge&&) = default;

  ~PartyAwaitingBitChallenge();

 private:
  friend class PartyAwaitingPosition;

  PartyAwaitingBitChallenge(
      size_t n,
      uint64_t v,
      const yacl::math::MPInt& v_blinding,
      size_t j,
      const PedersenGens& pc_gens,
      const yacl::math::MPInt& a_blinding,
      const yacl::math::MPInt& s_blinding,
      std::vector<yacl::math::MPInt> s_L,
      std::vector<yacl::math::MPInt> s_R);

  size_t n_;  // Bitsize of the range
  uint64_t v_;
  yacl::math::MPInt v_blinding_;
  size_t j_;  // Party's position in the aggregation
  const PedersenGens& pc_gens_;
  yacl::math::MPInt a_blinding_;
  yacl::math::MPInt s_blinding_;
  std::vector<yacl::math::MPInt> s_L_;
  std::vector<yacl::math::MPInt> s_R_;
};

/**
 * @brief A party which has committed to their polynomial coefficients
 * and is waiting for the polynomial challenge from the dealer.
 */
class PartyAwaitingPolyChallenge {
 public:
  /**
   * @brief Apply a polynomial challenge from the dealer to compute the proof share.
   * 
   * @param challenge The challenge from the dealer
   * @return ProofShare The party's share of the proof
   * @throws yacl::Exception if dealer is malicious
   */
  ProofShare ApplyChallenge(const PolyChallenge& challenge) const;

  // Deleted copy constructor and assignment to prevent copies
  PartyAwaitingPolyChallenge(const PartyAwaitingPolyChallenge&) = delete;
  PartyAwaitingPolyChallenge& operator=(const PartyAwaitingPolyChallenge&) = delete;
  
  // Allow move operations
  PartyAwaitingPolyChallenge(PartyAwaitingPolyChallenge&&) = default;
  PartyAwaitingPolyChallenge& operator=(PartyAwaitingPolyChallenge&&) = default;

  ~PartyAwaitingPolyChallenge();

 private:
  friend class PartyAwaitingBitChallenge;

  PartyAwaitingPolyChallenge(
      const yacl::math::MPInt& offset_zz,
      const VecPoly1& l_poly,
      const VecPoly1& r_poly,
      const Poly2& t_poly,
      const yacl::math::MPInt& v_blinding,
      const yacl::math::MPInt& a_blinding,
      const yacl::math::MPInt& s_blinding,
      const yacl::math::MPInt& t_1_blinding,
      const yacl::math::MPInt& t_2_blinding);

  yacl::math::MPInt offset_zz_;
  VecPoly1 l_poly_;
  VecPoly1 r_poly_;
  Poly2 t_poly_;
  yacl::math::MPInt v_blinding_;
  yacl::math::MPInt a_blinding_;
  yacl::math::MPInt s_blinding_;
  yacl::math::MPInt t_1_blinding_;
  yacl::math::MPInt t_2_blinding_;
};

} // namespace examples::zkp