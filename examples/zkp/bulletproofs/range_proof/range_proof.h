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

  RangeProof() = default;
  RangeProof(const RangeProof&) = delete;
  RangeProof(RangeProof&&) = default;
  RangeProof& operator=(RangeProof&&) = default;

  // Creates a range proof for multiple values
  static Error Create(
      const std::shared_ptr<yacl::crypto::EcGroup>& curve,
      const std::vector<yacl::math::MPInt>& values,
      const std::vector<yacl::math::MPInt>& blindings,
      const std::vector<yacl::crypto::EcPoint>& g_vec,
      const std::vector<yacl::crypto::EcPoint>& h_vec,
      const yacl::crypto::EcPoint& u,
      size_t bit_size,
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

  // Members
  yacl::crypto::EcPoint A_;            // Commitment A
  yacl::crypto::EcPoint S_;            // Commitment S
  yacl::crypto::EcPoint T1_;           // Commitment T1
  yacl::crypto::EcPoint T2_;           // Commitment T2
  yacl::math::MPInt t_x_;            // t(x) opening
  yacl::math::MPInt t_x_blinding_;   // Blinding factor for t(x)
  yacl::math::MPInt e_blinding_;   // Blinding factor for V
  InnerProductProof ipp_proof_;        // Inner product proof
};

} // namespace examples::zkp 