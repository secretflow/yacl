#pragma once

#include <cstdint>
#include <memory>
#include <vector>

#include "yacl/base/buffer.h"
#include "yacl/base/exception.h"
#include "yacl/crypto/ecc/ec_point.h"
#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/math/mpint/mp_int.h"
// Keep dependencies needed by the proof structure itself
#include "zkp/bulletproofs/inner_product_proof.h" // Assuming this matches rust::inner_product_proof::Proof
#include "zkp/bulletproofs/simple_transcript.h" // Assuming this matches rust::proof_transcript::ProofTranscript
#include "zkp/bulletproofs/util.h" // For VecPoly1, Poly2 and helpers

namespace examples::zkp {

/**
 * @brief Represents a single-party range proof based on the provided  code.
 *        Generators are derived internally via hashing, not from external Gens classes.
 */
class RangeProof {
 public:
  // Default constructors and assignment operators
  RangeProof() = default;
  RangeProof(const RangeProof& other) = default;
  RangeProof& operator=(const RangeProof& other) = default;
  RangeProof(RangeProof&& other) = default;
  RangeProof& operator=(RangeProof&& other) = default;

  /**
   * @brief Constructor matching the  struct fields.
   */
  RangeProof(
      const yacl::crypto::EcPoint& V,
      const yacl::crypto::EcPoint& A,
      const yacl::crypto::EcPoint& S,
      const yacl::crypto::EcPoint& T_1,
      const yacl::crypto::EcPoint& T_2,
      const yacl::math::MPInt& t_x,
      const yacl::math::MPInt& t_x_blinding,
      const yacl::math::MPInt& e_blinding,
      const InnerProductProof& ipp_proof); // Use the YACL IPP type

  // --- Single-Party Direct Proof Methods (based on provided  code) ---

  /**
   * @brief Creates a range proof directly for a single value.
   *        Uses hardcoded generator derivation via hashing, mirroring the  code.
   *
   * @param transcript Transcript for the protocol.
   * @param curve The elliptic curve group.
   * @param n Bitsize of the range (must be 8, 16, 32, or 64).
   * @param v Value to prove is in range [0, 2^n).
   * @param v_blinding Blinding factor for the value commitment.
   * @return RangeProof The generated proof.
   * @throws yacl::Exception if parameters are invalid or crypto operations fail.
   */
  static RangeProof GenerateProof(
        SimpleTranscript& transcript, // Use SimpleTranscript
        const std::shared_ptr<yacl::crypto::EcGroup>& curve,
        size_t n,
        uint64_t v,
        const yacl::math::MPInt& v_blinding);

  /**
   * @brief Verifies a direct single-party range proof created by GenerateProof.
   *        Uses hardcoded generator derivation via hashing, mirroring the  code.
   *
   * @param transcript Transcript for the protocol (must be in sync with prover).
   * @param curve The elliptic curve group.
   * @param n Bitsize of the range (must be 8, 16, 32, or 64).
   * @return bool True if the proof is valid, false otherwise.
   */
  bool Verify( // Renamed from VerifySingleProof for simplicity
        SimpleTranscript& transcript, // Use SimpleTranscript
        const std::shared_ptr<yacl::crypto::EcGroup>& curve,
        size_t n) const;


  // --- Serialization/Deserialization (adapted for the struct fields) ---
  yacl::Buffer ToBytes(const std::shared_ptr<yacl::crypto::EcGroup>& curve) const;

  static RangeProof FromBytes(
      const std::shared_ptr<yacl::crypto::EcGroup>& curve,
      const yacl::ByteContainerView& bytes);

  // --- Accessors for proof components (optional but useful) ---
  const yacl::crypto::EcPoint& GetV() const { return V_; }
  const yacl::crypto::EcPoint& GetA() const { return A_; }
  const yacl::crypto::EcPoint& GetS() const { return S_; }
  const yacl::crypto::EcPoint& GetT1() const { return T_1_; }
  const yacl::crypto::EcPoint& GetT2() const { return T_2_; }
  const yacl::math::MPInt& GetTx() const { return t_x_; }
  const yacl::math::MPInt& GetTxBlinding() const { return t_x_blinding_; }
  const yacl::math::MPInt& GetEBlinding() const { return e_blinding_; }
  const InnerProductProof& GetIPPProof() const { return ipp_proof_; }


 private:
  // Proof components mirroring  struct
  yacl::crypto::EcPoint V_;
  yacl::crypto::EcPoint A_;
  yacl::crypto::EcPoint S_;
  yacl::crypto::EcPoint T_1_;
  yacl::crypto::EcPoint T_2_;
  yacl::math::MPInt t_x_;
  yacl::math::MPInt t_x_blinding_;
  yacl::math::MPInt e_blinding_;
  InnerProductProof ipp_proof_; // Use the YACL IPP type

  // Static helper to compute delta, matching Rust's single-party delta
  static yacl::math::MPInt Delta(
      size_t n, // Only n needed for m=1
      const yacl::math::MPInt& y,
      const yacl::math::MPInt& z,
      const std::shared_ptr<yacl::crypto::EcGroup>& curve);

  // Static helper to generate G/H vectors, matching Rust's make_generators
   static std::vector<yacl::crypto::EcPoint> MakeGenerators(
       const yacl::crypto::EcPoint& base_point,
       size_t n,
       const std::shared_ptr<yacl::crypto::EcGroup>& curve);

};

// --- Utility Functions (Declarations assuming defined in util.h/cc) ---
yacl::math::MPInt SumOfPowers(
    const yacl::math::MPInt& base,
    size_t count,
    const std::shared_ptr<yacl::crypto::EcGroup>& curve);

std::vector<yacl::math::MPInt> ExpIterVector(
    const yacl::math::MPInt& base,
    size_t n,
    const std::shared_ptr<yacl::crypto::EcGroup>& curve);

yacl::math::MPInt InnerProduct(
    const std::vector<yacl::math::MPInt>& a,
    const std::vector<yacl::math::MPInt>& b,
    const std::shared_ptr<yacl::crypto::EcGroup>& curve);

std::vector<yacl::math::MPInt> AddVec(
    const std::vector<yacl::math::MPInt>& a,
    const std::vector<yacl::math::MPInt>& b,
    const std::shared_ptr<yacl::crypto::EcGroup>& curve);

yacl::crypto::EcPoint MultiScalarMul(
    const std::shared_ptr<yacl::crypto::EcGroup>& curve,
    const std::vector<yacl::math::MPInt>& scalars,
    const std::vector<yacl::crypto::EcPoint>& points);


} // namespace examples::zkp