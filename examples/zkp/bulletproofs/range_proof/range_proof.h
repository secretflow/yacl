#pragma once

#include <cstdint>
#include <memory>
#include <tuple>
#include <vector>

#include "yacl/base/buffer.h"
#include "yacl/base/exception.h"
#include "yacl/crypto/ecc/ec_point.h"
#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/math/mpint/mp_int.h"
#include "zkp/bulletproofs/generators.h"
#include "zkp/bulletproofs/inner_product_proof.h"
#include "zkp/bulletproofs/simple_transcript.h"

namespace examples::zkp {

// Forward declarations
class RangeProof;

/**
 * @brief Error codes for range proof operations
 */
enum class ProofError {
  kOk = 0,
  kInvalidBitsize,
  kInvalidGeneratorsLength,
  kWrongNumBlindingFactors,
  kVerificationError,
  kFormatError,
};

/**
 * @brief The RangeProof class represents a proof that one or more values are in a range.
 * 
 * The RangeProof class contains functions for creating and verifying aggregated range proofs.
 * The single-value case is implemented as a special case of aggregated range proofs.
 * 
 * The bitsize of the range, as well as the list of commitments to the values, are not included
 * in the proof, and must be known to the verifier.
 * 
 * This implementation requires that both the bitsize n and the aggregation size m be powers of two,
 * so that n = 8, 16, 32, 64 and m = 1, 2, 4, 8, 16, ...
 */
class RangeProof {
 public:
  /**
   * @brief Create a rangeproof for a given pair of value v and blinding scalar v_blinding.
   * 
   * @param bp_gens Bulletproof generators
   * @param pc_gens Pedersen generators
   * @param transcript Transcript for the protocol
   * @param v Value to prove is in range
   * @param v_blinding Blinding factor for value commitment
   * @param n Bitsize of the range proof (must be 8, 16, 32, or 64)
   * @return std::pair<RangeProof, yacl::crypto::EcPoint> Proof and value commitment
   * @throws yacl::Exception if parameters are invalid
   */
  static std::pair<RangeProof, yacl::crypto::EcPoint> CreateSingle(
      const std::shared_ptr<yacl::crypto::EcGroup>& curve,
      SimpleTranscript& transcript,
      uint64_t v,
      const yacl::math::MPInt& v_blinding,
      size_t n);

  /**
   * @brief Create a rangeproof for a set of values.
   * 
   * @param bp_gens Bulletproof generators
   * @param pc_gens Pedersen generators
   * @param transcript Transcript for the protocol
   * @param values Vector of values to prove are in range
   * @param blindings Vector of blinding factors for value commitments
   * @param n Bitsize of the range proof (must be 8, 16, 32, or 64)
   * @return std::pair<RangeProof, std::vector<yacl::crypto::EcPoint>> Proof and value commitments
   * @throws yacl::Exception if parameters are invalid
   */
  static std::pair<RangeProof, std::vector<yacl::crypto::EcPoint>> CreateMultiple(
      const std::shared_ptr<yacl::crypto::EcGroup>& curve,
      SimpleTranscript& transcript,
      const std::vector<uint64_t>& values,
      const std::vector<yacl::math::MPInt>& blindings,
      size_t n);

  /**
   * @brief Verifies a rangeproof for a given value commitment.
   * 
   * @param bp_gens Bulletproof generators
   * @param pc_gens Pedersen generators
   * @param transcript Transcript for the protocol
   * @param V Value commitment
   * @param n Bitsize of the range proof (must be 8, 16, 32, or 64)
   * @return ProofError Error code, kOk if successful
   */
  ProofError VerifySingle(
      const std::shared_ptr<yacl::crypto::EcGroup>& curve,
      SimpleTranscript& transcript,
      const yacl::crypto::EcPoint& V,
      size_t n) const;

  /**
   * @brief Verifies an aggregated rangeproof for the given value commitments.
   * 
   * @param bp_gens Bulletproof generators
   * @param pc_gens Pedersen generators
   * @param transcript Transcript for the protocol
   * @param value_commitments Vector of value commitments
   * @param n Bitsize of the range proof (must be 8, 16, 32, or 64)
   * @return ProofError Error code, kOk if successful
   */
  ProofError VerifyMultiple(
      const std::shared_ptr<yacl::crypto::EcGroup>& curve,
      SimpleTranscript& transcript,
      const std::vector<yacl::crypto::EcPoint>& value_commitments,
      size_t n) const;

  /**
   * @brief Serializes the proof into a byte buffer.
   * 
   * @return yacl::Buffer Serialized proof
   */
  yacl::Buffer ToBytes() const;
  
  /**
   * @brief Serializes the proof into a byte buffer with curve context.
   * 
   * @param curve Curve used to encode points
   * @return yacl::Buffer Serialized proof
   */
  yacl::Buffer ToBytes(const std::shared_ptr<yacl::crypto::EcGroup>& curve) const;

  /**
   * @brief Deserializes the proof from a byte buffer.
   * 
   * @param curve Curve for the proof
   * @param bytes Serialized proof
   * @return RangeProof Deserialized proof
   * @throws yacl::Exception if buffer cannot be parsed
   */
  static RangeProof FromBytes(
      const std::shared_ptr<yacl::crypto::EcGroup>& curve,
      yacl::ByteContainerView bytes);

  // Constructors and assignment operators
  RangeProof() = default;
  RangeProof(const RangeProof& other) = default;
  RangeProof& operator=(const RangeProof& other) = default;
  RangeProof(RangeProof&& other) = default;
  RangeProof& operator=(RangeProof&& other) = default;

  // Constructors with parameters
  RangeProof(
      const yacl::crypto::EcPoint& A,
      const yacl::crypto::EcPoint& S,
      const yacl::crypto::EcPoint& T_1,
      const yacl::crypto::EcPoint& T_2,
      const yacl::math::MPInt& t_x,
      const yacl::math::MPInt& t_x_blinding,
      const yacl::math::MPInt& e_blinding,
      const InnerProductProof& ipp_proof);

 private:
  // Helper methods for proof creation and verification
  
  /**
   * @brief Compute delta(y,z) = (z - z^2) * <1, y^(n*m)> - sum_{j=0}^{m-1} z^{j+3} * <1, 2^n>
   * 
   * @param n Bitsize of the range proof
   * @param m Number of aggregated proofs
   * @param y Challenge scalar y
   * @param z Challenge scalar z
   * @return yacl::math::MPInt The computed delta value
   */
  static yacl::math::MPInt Delta(
      size_t n,
      size_t m,
      const yacl::math::MPInt& y,
      const yacl::math::MPInt& z);

  // Fields representing components of the range proof
  yacl::crypto::EcPoint A_;       // Commitment to the bits of the value
  yacl::crypto::EcPoint S_;       // Commitment to the blinding factors
  yacl::crypto::EcPoint T_1_;     // Commitment to the t_1 coefficient of t(x)
  yacl::crypto::EcPoint T_2_;     // Commitment to the t_2 coefficient of t(x)
  yacl::math::MPInt t_x_;         // Evaluation of the polynomial t(x) at the challenge point x
  yacl::math::MPInt t_x_blinding_; // Blinding factor for the synthetic commitment to t(x)
  yacl::math::MPInt e_blinding_;  // Blinding factor for the synthetic commitment to inner-product
  InnerProductProof ipp_proof_;   // Proof data for the inner-product argument
};

/**
 * @brief Check if a number is a power of 2
 */
inline bool IsPowerOfTwo(size_t n) {
  return n > 0 && (n & (n - 1)) == 0;
}

} // namespace examples::zkp