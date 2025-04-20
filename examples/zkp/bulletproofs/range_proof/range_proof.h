#pragma once

#include <memory>
#include <utility>
#include <vector>

#include "yacl/base/buffer.h"
#include "yacl/base/byte_container_view.h"
#include "yacl/crypto/ecc/ec_point.h"
#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/math/mpint/mp_int.h"
#include "../inner_product_proof.h"

namespace examples::zkp {

class SimpleTranscript;

class RangeProof {
 public:
  // Error enum for verification results
  enum class Error {
    kOk = 0,
    kInvalidArgument,
    kInvalidInputSize, 
    kVerificationFailed,
  };

  // Creates a range proof for multiple values
  static Error Create(
      const std::shared_ptr<yacl::crypto::EcGroup>& curve,
      const std::vector<yacl::math::MPInt>& values,
      const std::vector<yacl::math::MPInt>& blindings,
      const std::vector<yacl::crypto::EcPoint>& g_vec,
      const std::vector<yacl::crypto::EcPoint>& h_vec,
      const yacl::crypto::EcPoint& u,
      RangeProof* proof);

  // Creates a single range proof for value in [0, 2^bit_size - 1]
  // Returns the proof and the Pedersen commitment V = g^value * h^blinding
  static std::pair<RangeProof, yacl::crypto::EcPoint> CreateSingle(
      const std::shared_ptr<yacl::crypto::EcGroup>& curve,
      SimpleTranscript& transcript,
      const yacl::math::MPInt& value,
      const yacl::math::MPInt& blinding,
      size_t bit_size);

  // Verifies a range proof for multiple values
  Error Verify(
      const std::shared_ptr<yacl::crypto::EcGroup>& curve,
      size_t n,
      SimpleTranscript& transcript,
      const std::vector<yacl::math::MPInt>& G_factors,
      const std::vector<yacl::math::MPInt>& H_factors,
      const yacl::crypto::EcPoint& P,
      const yacl::crypto::EcPoint& Q,
      const std::vector<yacl::crypto::EcPoint>& G_vec,
      const std::vector<yacl::crypto::EcPoint>& H_vec) const;

  // Verifies a single range proof against commitment V
  Error VerifySingle(
      const std::shared_ptr<yacl::crypto::EcGroup>& curve,
      SimpleTranscript& transcript,
      const yacl::crypto::EcPoint& V,
      size_t bit_size) const;

  // Serialization
  yacl::Buffer ToBytes() const;
  static RangeProof FromBytes(
      const std::shared_ptr<yacl::crypto::EcGroup>& curve,
      const yacl::ByteContainerView& bytes);

 private:
  // Commitment to the bits of the value
  yacl::crypto::EcPoint A_;
  // Commitment to the blinding factors
  yacl::crypto::EcPoint S_;
  // Commitment to the t_1 coefficient of t(x)
  yacl::crypto::EcPoint T1_;
  // Commitment to the t_2 coefficient of t(x)
  yacl::crypto::EcPoint T2_;
  // Evaluation of t(x) at the challenge point x
  yacl::math::MPInt t_x_;
  // Blinding factor for t(x)
  yacl::math::MPInt t_x_blinding_;
  // Blinding factor for the inner product proof
  yacl::math::MPInt e_blinding_;
  // Inner product proof
  InnerProductProof ipp_proof_;
};

} // namespace examples::zkp 