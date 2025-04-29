#pragma once

#include <cstdint>
#include <memory>
#include <vector>
#include <utility> // For std::pair

#include "yacl/base/exception.h"
#include "yacl/crypto/ecc/ec_point.h"
#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/math/mpint/mp_int.h"

// *** FIX: Include the full definition for VecPoly1 and Poly2 ***
#include "zkp/bulletproofs/util.h"
// Forward declare other dependent types from other headers
namespace examples::zkp {
class BulletproofGens;
class PedersenGens;
class BitCommitment;
class BitChallenge;
class PolyCommitment;
class PolyChallenge;
class ProofShare;
// VecPoly1 and Poly2 are now fully defined via util.h
} // namespace examples::zkp


namespace examples::zkp {

// Forward declarations for state classes
class PartyAwaitingPosition;
class PartyAwaitingBitChallenge;
class PartyAwaitingPolyChallenge;

/**
 * @brief Used to construct a party for the aggregated rangeproof MPC protocol.
 *        Acts as a factory for the initial state.
 */
class Party {
 public:
  /**
   * @brief Constructs a PartyAwaitingPosition with the given rangeproof parameters.
   *
   * @param bp_gens Bulletproof generators (reference, must outlive party states).
   * @param pc_gens Pedersen generators (reference, must outlive party states).
   * @param v Value to prove is in range.
   * @param v_blinding Blinding factor for the value commitment.
   * @param n Bitsize of the range (must be 8, 16, 32, or 64).
   * @return PartyAwaitingPosition The initial party state.
   * @throws yacl::Exception if parameters are invalid.
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
 *        Represents the initial state of the party.
 */
class PartyAwaitingPosition {
 public:
  /**
   * @brief Assigns a position in the aggregated proof to this party.
   *        Generates the party's bit commitments (V, A, S).
   *
   * @param j Position index assigned by the dealer (0-based).
   * @return std::pair<PartyAwaitingBitChallenge, BitCommitment> Next state and the commitment message.
   * @throws yacl::Exception if position j is invalid or generators are insufficient.
   */
  std::pair<PartyAwaitingBitChallenge, BitCommitment> AssignPosition(size_t j) const;

  

  // Prevent copying, allow moving
  PartyAwaitingPosition(const PartyAwaitingPosition&) = delete;
  PartyAwaitingPosition& operator=(const PartyAwaitingPosition&) = delete;
  PartyAwaitingPosition(PartyAwaitingPosition&&) = default;
  PartyAwaitingPosition& operator=(PartyAwaitingPosition&&) = default;

  ~PartyAwaitingPosition();

 private:
  friend class Party; // Allow Party::New to call the private constructor

  PartyAwaitingPosition(
      const BulletproofGens& bp_gens,
      const PedersenGens& pc_gens,
      uint64_t v,
      const yacl::math::MPInt& v_blinding,
      size_t n);

  // *** Declaration Order Matters for Initializer List ***
  const BulletproofGens& bp_gens_;
  const PedersenGens& pc_gens_;
  size_t n_;
  uint64_t v_;
  yacl::math::MPInt v_blinding_;
  yacl::crypto::EcPoint V_;
};

/**
 * @brief A party which has committed to the bits of its value
 *        and is waiting for the aggregated bit challenge from the dealer.
 */

class PartyAwaitingBitChallenge {
 public:
  /**
   * @brief Apply a bit challenge from the dealer to compute commitments
   *        to the party's polynomial coefficients (T1, T2).
   *
   * @param challenge The BitChallenge (y, z) received from the dealer.
   * @return std::pair<PartyAwaitingPolyChallenge, PolyCommitment> Next state and the commitment message.
   */
  std::pair<PartyAwaitingPolyChallenge, PolyCommitment> ApplyChallenge(
      const BitChallenge& challenge) const;

  // Prevent copying, allow moving
  PartyAwaitingBitChallenge(const PartyAwaitingBitChallenge&) = delete;
  PartyAwaitingBitChallenge& operator=(const PartyAwaitingBitChallenge&) = delete;
  PartyAwaitingBitChallenge(PartyAwaitingBitChallenge&&) = default;
  PartyAwaitingBitChallenge& operator=(PartyAwaitingBitChallenge&&) = default;

  ~PartyAwaitingBitChallenge();

  PartyAwaitingBitChallenge(
      size_t n, 
      size_t j,
      const PedersenGens& pc_gens,
      const std::shared_ptr<yacl::crypto::EcGroup>& curve,
      uint64_t v,
      const yacl::math::MPInt& v_blinding,
      const yacl::math::MPInt& a_blinding,
      const yacl::math::MPInt& s_blinding,
      std::vector<yacl::math::MPInt> s_L,
      std::vector<yacl::math::MPInt> s_R);

 private:
  friend class PartyAwaitingPosition; // Allow previous state to construct this

  // Proof parameters and external references
  size_t n_;
  size_t j_;
  const PedersenGens& pc_gens_;
  std::shared_ptr<yacl::crypto::EcGroup> curve_; // Store curve pointer
  // Secrets held by this state
  uint64_t v_;
  yacl::math::MPInt v_blinding_;
  yacl::math::MPInt a_blinding_;
  yacl::math::MPInt s_blinding_;
  std::vector<yacl::math::MPInt> s_L_;
  std::vector<yacl::math::MPInt> s_R_;
};

/**
 * @brief A party which has committed to their polynomial coefficients (T1, T2)
 *        and is waiting for the polynomial challenge (x) from the dealer.
 */
class PartyAwaitingPolyChallenge {
 public:
  /**
   * @brief Apply a polynomial challenge from the dealer to compute the
   *        party's final proof share.
   *
   * @param challenge The PolyChallenge (x) received from the dealer.
   * @return ProofShare The party's share of the proof.
   * @throws yacl::Exception if the challenge x is zero (malicious dealer).
   */
  ProofShare ApplyChallenge(const PolyChallenge& challenge) const;

  // Prevent copying, allow moving
  PartyAwaitingPolyChallenge(const PartyAwaitingPolyChallenge&) = delete;
  PartyAwaitingPolyChallenge& operator=(const PartyAwaitingPolyChallenge&) = delete;
  PartyAwaitingPolyChallenge(PartyAwaitingPolyChallenge&&) = default;
  PartyAwaitingPolyChallenge& operator=(PartyAwaitingPolyChallenge&&) = default;

  ~PartyAwaitingPolyChallenge();

  // Constructor with parameters in the same order as the member variables
  PartyAwaitingPolyChallenge(
      const yacl::math::MPInt& offset_zz,
      VecPoly1&& l_poly,
      VecPoly1&& r_poly,
      const Poly2& t_poly,
      const yacl::math::MPInt& v_blinding,
      const yacl::math::MPInt& a_blinding,
      const yacl::math::MPInt& s_blinding,
      const yacl::math::MPInt& t_1_blinding,
      const yacl::math::MPInt& t_2_blinding,
      const std::shared_ptr<yacl::crypto::EcGroup>& curve);

 private:
  friend class PartyAwaitingBitChallenge; // Allow previous state to construct this

  // The order of member declarations should match the initialization order in constructor
  // Precomputed values
  yacl::math::MPInt offset_zz_;
  // Polynomials (potentially large, manage ownership carefully)
  VecPoly1 l_poly_;
  VecPoly1 r_poly_;
  Poly2 t_poly_;
  // Secrets held by this state
  yacl::math::MPInt v_blinding_;
  yacl::math::MPInt a_blinding_;
  yacl::math::MPInt s_blinding_;
  yacl::math::MPInt t_1_blinding_;
  yacl::math::MPInt t_2_blinding_;
  // External reference - moved to the end to match initialization order
  std::shared_ptr<yacl::crypto::EcGroup> curve_;
};

} // namespace examples::zkp