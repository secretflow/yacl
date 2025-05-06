#pragma once

#include <cstdint>
#include <memory>
#include <vector>

#include "yacl/base/buffer.h"
#include "yacl/base/exception.h"
#include "yacl/crypto/ecc/ec_point.h"
#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/math/mpint/mp_int.h"
#include "zkp/bulletproofs/generators.h"
#include "zkp/bulletproofs/ipa/inner_product_proof.h"
#include "zkp/bulletproofs/simple_transcript.h"

namespace examples::zkp {

/**
 * @brief The RangeProofMPC class represents a proof that one or more values
 * are in a range.
 *
 * This implementation requires that both the bitsize n and the aggregation size m
 * be powers of two, so that n = 8, 16, 32, 64 and m = 1, 2, 4, 8, 16, ...
 */
class RangeProofMPC {
 public:
  // Default constructors and assignment operators
  RangeProofMPC() = default;
  RangeProofMPC(const RangeProofMPC& other) = default;
  RangeProofMPC& operator=(const RangeProofMPC& other) = default;
  RangeProofMPC(RangeProofMPC&& other) = default;
  RangeProofMPC& operator=(RangeProofMPC&& other) = default;

  /**
   * @brief Constructor with all components
   */
  RangeProofMPC(
      const yacl::crypto::EcPoint& A,
      const yacl::crypto::EcPoint& S,
      const yacl::crypto::EcPoint& T_1,
      const yacl::crypto::EcPoint& T_2,
      const yacl::math::MPInt& t_x,
      const yacl::math::MPInt& t_x_blinding,
      const yacl::math::MPInt& e_blinding,
      const InnerProductProof& ipp_proof);

  /**
   * @brief Create a range proof for a single value
   * 
   * @param curve The elliptic curve group
   * @param transcript Transcript for the protocol
   * @param v Value to prove is in range
   * @param v_blinding Blinding factor for the value commitment
   * @param n Bitsize of the range (must be 8, 16, 32, or 64)
   * @return std::pair<RangeProof, yacl::crypto::EcPoint> Proof and value commitment
   */
  static std::pair<RangeProofMPC, yacl::crypto::EcPoint> CreateSingle(
      const BulletproofGens& bp_gens,
      const PedersenGens& pc_gens,
      SimpleTranscript& transcript,
      uint64_t v,
      const yacl::math::MPInt& v_blinding,
      size_t n);

  /**
   * @brief Create a range proof for multiple values
   * 
   * @param curve The elliptic curve group
   * @param transcript Transcript for the protocol
   * @param values Values to prove are in range
   * @param blindings Blinding factors for the value commitments
   * @param n Bitsize of the range (must be 8, 16, 32, or 64)
   * @return std::pair<RangeProof, std::vector<yacl::crypto::EcPoint>> Proof and value commitments
   */
  static std::pair<RangeProofMPC, std::vector<yacl::crypto::EcPoint>> CreateMultiple(
      const BulletproofGens& bp_gens,
      const PedersenGens& pc_gens,
      SimpleTranscript& transcript,
      const std::vector<uint64_t>& values,
      const std::vector<yacl::math::MPInt>& blindings,
      size_t n);

  /**
   * @brief Verify a range proof for a single value commitment
   * 
   * @param curve The elliptic curve group
   * @param transcript Transcript for the protocol
   * @param V Value commitment
   * @param n Bitsize of the range (must be 8, 16, 32, or 64)
   * @return bool True if verification succeeds
   */
  bool VerifySingle(
      const BulletproofGens& bp_gens,
      const PedersenGens& pc_gens,
      SimpleTranscript& transcript,
      const yacl::crypto::EcPoint& V,
      size_t n) const;

  /**
   * @brief Verify a range proof for multiple value commitments
   * 
   * @param curve The elliptic curve group
   * @param transcript Transcript for the protocol
   * @param value_commitments Value commitments
   * @param n Bitsize of the range (must be 8, 16, 32, or 64)
   * @return bool True if verification succeeds
   */
  bool VerifyMultiple(
      const BulletproofGens& bp_gens,
      const PedersenGens& pc_gens,
      SimpleTranscript& transcript,
      const std::vector<yacl::crypto::EcPoint>& value_commitments,
      size_t n) const;

  /**
   * @brief Serialize the proof to bytes
   */
  yacl::Buffer ToBytes(const std::shared_ptr<yacl::crypto::EcGroup>& curve) const;

  /**
   * @brief Deserialize a proof from bytes
   */
  static RangeProofMPC FromBytes(
      const std::shared_ptr<yacl::crypto::EcGroup>& curve,
      const yacl::ByteContainerView& bytes);

  /**
    * @brief Compute the delta value used in verification
    */
  static yacl::math::MPInt Delta(
      size_t n,
      size_t m,
      const yacl::math::MPInt& y,
      const yacl::math::MPInt& z,
      const std::shared_ptr<yacl::crypto::EcGroup>& curve);

 private:

  // Proof components
  yacl::crypto::EcPoint A_;        // Commitment to the bits of the value
  yacl::crypto::EcPoint S_;        // Commitment to the blinding factors
  yacl::crypto::EcPoint T_1_;      // Commitment to the t_1 coefficient of t(x)
  yacl::crypto::EcPoint T_2_;      // Commitment to the t_2 coefficient of t(x)
  yacl::math::MPInt t_x_;          // Evaluation of t(x) at the challenge point x
  yacl::math::MPInt t_x_blinding_; // Blinding for the t(x) commitment
  yacl::math::MPInt e_blinding_;   // Blinding for the inner product commitment
  InnerProductProof ipp_proof_;    // Inner product proof
};

/**
 * @brief Check if a number is a power of 2
 */
inline bool IsPowerOfTwo(size_t n) {
  return n > 0 && (n & (n - 1)) == 0;
}

/**
 * @brief Compute sum of powers: base^0 + base^1 + ... + base^(n-1)
 */
inline yacl::math::MPInt SumOfPowers(
    const yacl::math::MPInt& base,
    size_t n,
    const std::shared_ptr<yacl::crypto::EcGroup>& curve) {
  if (base == yacl::math::MPInt(1)) {
    return yacl::math::MPInt(n);
  }
  
  // Using the formula: sum = (base^n - 1)/(base - 1)
  yacl::math::MPInt base_pow_n = base.PowMod(yacl::math::MPInt(n), curve->GetOrder());
  yacl::math::MPInt numerator = base_pow_n.SubMod(yacl::math::MPInt(1), curve->GetOrder());
  yacl::math::MPInt denominator = base.SubMod(yacl::math::MPInt(1), curve->GetOrder());
  yacl::math::MPInt inv_denominator = denominator.InvertMod(curve->GetOrder());
  
  return numerator.MulMod(inv_denominator, curve->GetOrder());
}

/**
 * @brief Compute scalar exponentiation: base^exp
 */
inline yacl::math::MPInt ScalarExp(
    const yacl::math::MPInt& base,
    size_t exp,
    const std::shared_ptr<yacl::crypto::EcGroup>& curve) {
  return base.PowMod(yacl::math::MPInt(exp), curve->GetOrder());
}

} // namespace examples::zkp