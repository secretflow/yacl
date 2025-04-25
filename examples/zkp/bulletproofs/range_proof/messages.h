#pragma once

#include <cstdint>
#include <memory>
#include <vector>

#include "yacl/base/exception.h"
#include "yacl/crypto/ecc/ec_point.h"
#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/math/mpint/mp_int.h"
#include "zkp/bulletproofs/generators.h"

namespace examples::zkp {

/**
 * @brief A commitment to the bits of a party's value.
 */
class BitCommitment {
 public:
  BitCommitment() = default;
  
  BitCommitment(
      const yacl::crypto::EcPoint& V_j,
      const yacl::crypto::EcPoint& A_j,
      const yacl::crypto::EcPoint& S_j);
  
  // Getters
  const yacl::crypto::EcPoint& GetV() const { return V_j_; }
  const yacl::crypto::EcPoint& GetA() const { return A_j_; }
  const yacl::crypto::EcPoint& GetS() const { return S_j_; }
  
  // Serialization methods
  yacl::Buffer ToBytes() const;
  static BitCommitment FromBytes(
      const std::shared_ptr<yacl::crypto::EcGroup>& curve,
      yacl::ByteContainerView bytes);

 private:
  yacl::crypto::EcPoint V_j_;  // Value commitment
  yacl::crypto::EcPoint A_j_;  // Commitment to bit decomposition
  yacl::crypto::EcPoint S_j_;  // Commitment to blinding factors
};

/**
 * @brief Challenge values derived from all parties' BitCommitments.
 */
class BitChallenge {
 public:
  BitChallenge() = default;
  
  BitChallenge(
      const yacl::math::MPInt& y,
      const yacl::math::MPInt& z);
  
  // Getters
  const yacl::math::MPInt& GetY() const { return y_; }
  const yacl::math::MPInt& GetZ() const { return z_; }
  
  // Serialization methods
  yacl::Buffer ToBytes() const;
  static BitChallenge FromBytes(yacl::ByteContainerView bytes);

 private:
  yacl::math::MPInt y_;  // Challenge for bit decomposition
  yacl::math::MPInt z_;  // Challenge for bit decomposition
};

/**
 * @brief A commitment to a party's polynomial coefficients.
 */
class PolyCommitment {
 public:
  PolyCommitment() = default;
  
  PolyCommitment(
      const yacl::crypto::EcPoint& T_1_j,
      const yacl::crypto::EcPoint& T_2_j);
  
  // Getters
  const yacl::crypto::EcPoint& GetT1() const { return T_1_j_; }
  const yacl::crypto::EcPoint& GetT2() const { return T_2_j_; }
  
  // Serialization methods
  yacl::Buffer ToBytes() const;
  static PolyCommitment FromBytes(
      const std::shared_ptr<yacl::crypto::EcGroup>& curve,
      yacl::ByteContainerView bytes);

 private:
  yacl::crypto::EcPoint T_1_j_;  // Commitment to t_1
  yacl::crypto::EcPoint T_2_j_;  // Commitment to t_2
};

/**
 * @brief Challenge values derived from all parties' PolyCommitments.
 */
class PolyChallenge {
 public:
  PolyChallenge() = default;
  
  explicit PolyChallenge(const yacl::math::MPInt& x);
  
  // Getters
  const yacl::math::MPInt& GetX() const { return x_; }
  
  // Serialization methods
  yacl::Buffer ToBytes() const;
  static PolyChallenge FromBytes(yacl::ByteContainerView bytes);

 private:
  yacl::math::MPInt x_;  // Challenge for polynomial evaluation
};

/**
 * @brief A party's proof share, ready for aggregation into the final RangeProof.
 */
class ProofShare {
 public:
  ProofShare() = default;
  
  ProofShare(
      const yacl::math::MPInt& t_x,
      const yacl::math::MPInt& t_x_blinding,
      const yacl::math::MPInt& e_blinding,
      std::vector<yacl::math::MPInt> l_vec,
      std::vector<yacl::math::MPInt> r_vec);
  
  // Getters
  const yacl::math::MPInt& GetTX() const { return t_x_; }
  const yacl::math::MPInt& GetTXBlinding() const { return t_x_blinding_; }
  const yacl::math::MPInt& GetEBlinding() const { return e_blinding_; }
  const std::vector<yacl::math::MPInt>& GetLVec() const { return l_vec_; }
  const std::vector<yacl::math::MPInt>& GetRVec() const { return r_vec_; }
  
  /**
   * @brief Checks consistency of all sizes in the proof share.
   * 
   * @param expected_n Expected size of l/r vectors
   * @param bp_gens Bulletproof generators
   * @param j Party index
   * @throws yacl::Exception if sizes are inconsistent
   */
  void CheckSize(
      size_t expected_n,
      const BulletproofGens& bp_gens,
      size_t j) const;
  
  /**
   * @brief Audit an individual proof share to determine whether it is malformed.
   * 
   * @param bp_gens Bulletproof generators
   * @param pc_gens Pedersen generators
   * @param j Party index
   * @param bit_commitment Party's bit commitment
   * @param bit_challenge Bit challenge from dealer
   * @param poly_commitment Party's polynomial commitment
   * @param poly_challenge Polynomial challenge from dealer
   * @throws yacl::Exception if the audit fails
   */
  void AuditShare(
      const BulletproofGens& bp_gens,
      const PedersenGens& pc_gens,
      size_t j,
      const BitCommitment& bit_commitment,
      const BitChallenge& bit_challenge,
      const PolyCommitment& poly_commitment,
      const PolyChallenge& poly_challenge) const;
  
  // Serialization methods
  yacl::Buffer ToBytes() const;
  static ProofShare FromBytes(yacl::ByteContainerView bytes);

 private:
  yacl::math::MPInt t_x_;            // Value of t(x)
  yacl::math::MPInt t_x_blinding_;   // Blinding factor for t(x)
  yacl::math::MPInt e_blinding_;     // Blinding factor
  std::vector<yacl::math::MPInt> l_vec_;  // Left vector
  std::vector<yacl::math::MPInt> r_vec_;  // Right vector
};

/**
 * @brief Calculate inner product of two scalar vectors.
 * 
 * @param a First vector
 * @param b Second vector
 * @return yacl::math::MPInt Inner product result
 * @throws yacl::Exception if vectors have different sizes
 */
yacl::math::MPInt InnerProduct(
    const std::vector<yacl::math::MPInt>& a,
    const std::vector<yacl::math::MPInt>& b);

/**
 * @brief Create an iterator over powers of a scalar: s^0, s^1, s^2, ...
 * 
 * @param s Base scalar
 * @return Vector of powers
 * @param n Number of powers to generate
 */
std::vector<yacl::math::MPInt> ExpIterVector(const yacl::math::MPInt& s, size_t n);

/**
 * @brief Calculate the sum of powers: s^0 + s^1 + ... + s^(n-1)
 * 
 * @param s Base scalar
 * @param n Number of terms
 * @return yacl::math::MPInt Sum of powers
 */
yacl::math::MPInt SumOfPowers(const yacl::math::MPInt& s, size_t n);

/**
 * @brief Calculate scalar exponentiation x^n in variable time.
 * 
 * @param x Base
 * @param n Exponent
 * @return yacl::math::MPInt Result
 */
yacl::math::MPInt ScalarExpVartime(const yacl::math::MPInt& x, uint64_t n);

} // namespace examples::zkp