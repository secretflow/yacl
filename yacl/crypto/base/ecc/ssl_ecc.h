// Copyright 2022 Ant Group Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

#include <array>
#include <memory>
#include <string>
#include <vector>

#include "absl/types/span.h"
#include "openssl/bn.h"
#include "openssl/ec.h"
#include "openssl/evp.h"

#include "yacl/base/byte_container_view.h"
#include "yacl/crypto/base/symmetric_crypto.h"

namespace yacl::crypto {

// In most appliations, the default key length of private key is 256 bits, but
// different key sizes are possible to use, see details in
//  - SP 800-56A Rev. 3: Recommendation for Pair-Wise Key-Establishment Schemes
//    Using Discrete Logarithm Cryptography
//    link: https://csrc.nist.gov/publications/detail/sp/800-56a/rev-3/final
//
// EC points (compressed): coordinate + 1 (odd/even) = key_length + 1 bits
// Integers (in the range of curve's field size): 256 bits
//
// Private key length for other curves:
//  - secp192r1: 192 bits
//  - sect233k1: 233 bits
//  - secp224k1: 224 bits
//  - sect283k1: 283 bits
//  - p384/secp384r1: 384 bits
//  - sect409r1: 409 bits
//  - Curve41417: 414 bits
//  - Curve448-Goldilocks: 448 bits
//  - M-511: 511 bits
//  - P-521: 521 bits
//  - sect571k1: 571 bits
//
// Avaliable Ecc Group Ids:
// constexpr auto kEcGroupId = NID_secp256k1;
// constexpr auto kEcGroupId = NID_sm2;
//
constexpr size_t kEc256KeyLength = 32;
constexpr size_t kEcPointCompressLength = 33;

#define INTERNAL_WRAP_SSL_ECC_TYPE(TYPE, DELETER) \
  struct TYPE##_DELETER {                         \
   public:                                        \
    void operator()(TYPE* x) { DELETER(x); }      \
  };                                              \
  using TYPE##_PTR = std::unique_ptr<TYPE, TYPE##_DELETER>;

INTERNAL_WRAP_SSL_ECC_TYPE(BN_CTX, BN_CTX_free)
INTERNAL_WRAP_SSL_ECC_TYPE(BIGNUM, BN_free)
INTERNAL_WRAP_SSL_ECC_TYPE(EC_GROUP, EC_GROUP_free)
INTERNAL_WRAP_SSL_ECC_TYPE(EC_POINT, EC_POINT_free)

class BigNum {
 public:
  BigNum() : bn_ptr_(BN_new()) {}
  explicit BigNum(ByteContainerView bytes) : bn_ptr_(BN_new()) {
    FromBytes(bytes);
  }

  BIGNUM* get() const { return bn_ptr_.get(); }

  std::vector<uint8_t> ToBytes();
  void ToBytes(absl::Span<uint8_t> bytes);

  void FromBytes(ByteContainerView bytes);
  void FromBytes(ByteContainerView bytes, const BigNum& p);

  void ModInplace(const BigNum& p);
  BigNum ModInverse(const BigNum& p);
  BigNum ModAdd(const BigNum& in, const BigNum& p);
  BigNum ModMul(const BigNum& in, const BigNum& p);

 private:
  BIGNUM_PTR bn_ptr_;
};

class EcGroup {
 public:
  explicit EcGroup(int ec_group_nid)
      : EcGroup(EC_GROUP_new_by_curve_name(ec_group_nid)) {}
  explicit EcGroup(EC_GROUP* group) : group_ptr_(group) {
    BN_CTX_PTR bn_ctx(yacl::CheckNotNull(BN_CTX_new()));

    YACL_ENFORCE(EC_GROUP_get_curve(group_ptr_.get(), bn_p.get(), bn_a.get(),
                                    bn_b.get(), bn_ctx.get()) == 1);
    YACL_ENFORCE(
        EC_GROUP_get_order(group_ptr_.get(), bn_n.get(), bn_ctx.get()) == 1);
  }

  EC_GROUP* get() { return group_ptr_.get(); }
  const EC_GROUP* get() const { return group_ptr_.get(); }

  BigNum bn_p;
  BigNum bn_a;
  BigNum bn_b;
  BigNum bn_n;

 private:
  EC_GROUP_PTR group_ptr_;
};

class EcPoint {
 public:
  explicit EcPoint(const EcGroup& group)
      : group_ref_(group), point_ptr_(EC_POINT_new(group_ref_.get())) {}

  EC_POINT* get() { return point_ptr_.get(); }
  const EC_POINT* get() const { return point_ptr_.get(); }
  const EcGroup& get_group() { return group_ref_; }

  std::vector<uint8_t> ToBytes();
  void ToBytes(absl::Span<uint8_t> bytes);

  void FromBytes(const EcGroup& ec_group, ByteContainerView bytes);

  EcPoint PointMul(const EcGroup& ec_group, const BigNum& bn);
  EcPoint PointAdd(const EcGroup& ec_group, const EcPoint& ec_point);
  static EcPoint BasePointMul(const EcGroup& ec_group, const BigNum& bn);

 private:
  const EcGroup& group_ref_;
  EC_POINT_PTR point_ptr_;
};

}  // namespace yacl::crypto
