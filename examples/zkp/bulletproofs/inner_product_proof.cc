#include "zkp/bulletproofs/inner_product_proof.h"

#include <vector>
#include "yacl/crypto/ecc/ec_point.h"
#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/crypto/tools/ro.h"
#include "yacl/math/mpint/mp_int.h"

namespace examples::zkp {

using yacl::crypto::EcPoint;
using yacl::crypto::RandomOracle;
using yacl::math::MPInt;

MPInt InnerProduct(const std::vector<MPInt>& a, const std::vector<MPInt>& b) {
  MPInt result;
  for (size_t i = 0; i < a.size(); ++i) {
    result += a[i] * b[i];
  }
  return result;
}

InnerProductProof InnerProductProof::Create(
    yacl::crypto::RandomOracle* transcript,
    const yacl::crypto::EcPoint& Q,
    const std::vector<yacl::math::MPInt>& G_factors,
    const std::vector<yacl::math::MPInt>& H_factors,
    const std::vector<yacl::crypto::EcPoint>& G_vec,
    const std::vector<yacl::crypto::EcPoint>& H_vec,
    const std::vector<yacl::math::MPInt>& a_vec,
    const std::vector<yacl::math::MPInt>& b_vec) {
  // TODO: 实现证明创建逻辑
  (void)transcript;
  (void)Q;
  (void)G_factors;
  (void)H_factors;
  (void)G_vec;
  (void)H_vec;
  (void)a_vec;
  (void)b_vec;
  return InnerProductProof();
}

InnerProductProof::Error InnerProductProof::Verify(
    size_t n,
    yacl::crypto::RandomOracle* transcript,
    const std::vector<yacl::math::MPInt>& G_factors,
    const std::vector<yacl::math::MPInt>& H_factors,
    const yacl::crypto::EcPoint& P,
    const yacl::crypto::EcPoint& Q,
    const std::vector<yacl::crypto::EcPoint>& G_vec,
    const std::vector<yacl::crypto::EcPoint>& H_vec) const {
  // TODO: 实现证明验证逻辑
  (void)n;
  (void)transcript;
  (void)G_factors;
  (void)H_factors;
  (void)P;
  (void)Q;
  (void)G_vec;
  (void)H_vec;
  return Error::kOk;
}

}  // namespace examples::zkp