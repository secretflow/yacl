#pragma once

#include <vector>
#include "yacl/crypto/ecc/ec_point.h"
#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/crypto/tools/ro.h"
#include "yacl/math/mpint/mp_int.h"
#include "yacl/crypto/hash/hash_utils.h"

namespace examples::zkp {

class InnerProductProof {
 public:
  enum class Error {
    kOk,
    kInvalidProof,
    kInvalidInput,
  };

  // 创建内积证明
  static InnerProductProof Create(
      yacl::crypto::RandomOracle* transcript,
      const yacl::crypto::EcPoint& Q,
      const std::vector<yacl::math::MPInt>& G_factors,
      const std::vector<yacl::math::MPInt>& H_factors,
      const std::vector<yacl::crypto::EcPoint>& G_vec,
      const std::vector<yacl::crypto::EcPoint>& H_vec,
      const std::vector<yacl::math::MPInt>& a_vec,
      const std::vector<yacl::math::MPInt>& b_vec);

  // 验证内积证明
  Error Verify(
      size_t n,
      yacl::crypto::RandomOracle* transcript,
      const std::vector<yacl::math::MPInt>& G_factors,
      const std::vector<yacl::math::MPInt>& H_factors,
      const yacl::crypto::EcPoint& P,
      const yacl::crypto::EcPoint& Q,
      const std::vector<yacl::crypto::EcPoint>& G_vec,
      const std::vector<yacl::crypto::EcPoint>& H_vec) const;

 private:
  std::vector<yacl::math::MPInt> proof_;
};

}  // namespace examples::zkp