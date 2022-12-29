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

#include "yacl/crypto/base/ecc/ssl_ecc.h"

#include "yacl/base/byte_container_view.h"

namespace yacl::crypto {

void BigNum::ToBytes(absl::Span<uint8_t> bytes) {
  YACL_ENFORCE(BN_bn2binpad(bn_ptr_.get(), bytes.data(), kEc256KeyLength) != -1,
               "input byte container is too small!");
}

std::vector<uint8_t> BigNum::ToBytes() {
  std::vector<uint8_t> out(kEc256KeyLength);
  BN_bn2binpad(bn_ptr_.get(), out.data(), kEc256KeyLength);
  return out;
}

void BigNum::FromBytes(ByteContainerView bytes) {
  // converts the bytes to big_num in big-endian form
  YACL_ENFORCE(nullptr != BN_bin2bn(bytes.data(), bytes.size(), bn_ptr_.get()));
}

void BigNum::FromBytes(ByteContainerView bytes, const BigNum& p) {
  BN_CTX_PTR bn_ctx(yacl::CheckNotNull(BN_CTX_new()));
  FromBytes(bytes);
  BN_nnmod(bn_ptr_.get(), bn_ptr_.get(), p.get(), bn_ctx.get());
}

void BigNum::ModInplace(const BigNum& p) {
  BN_CTX_PTR bn_ctx(yacl::CheckNotNull(BN_CTX_new()));
  BN_nnmod(bn_ptr_.get(), bn_ptr_.get(), p.get(), bn_ctx.get());
}

BigNum BigNum::ModInverse(const BigNum& p) {
  BN_CTX_PTR bn_ctx(yacl::CheckNotNull(BN_CTX_new()));
  BigNum bn_inv;
  BN_mod_inverse(bn_inv.get(), bn_ptr_.get(), p.get(), bn_ctx.get());
  return bn_inv;
}

BigNum BigNum::ModAdd(const BigNum& in, const BigNum& p) {
  BN_CTX_PTR bn_ctx(yacl::CheckNotNull(BN_CTX_new()));
  BigNum bn_res;
  BN_mod_add(bn_res.get(), bn_ptr_.get(), in.get(), p.get(), bn_ctx.get());
  return bn_res;
}

BigNum BigNum::ModMul(const BigNum& in, const BigNum& p) {
  BN_CTX_PTR bn_ctx(yacl::CheckNotNull(BN_CTX_new()));
  BigNum bn_res;
  BN_mod_mul(bn_res.get(), bn_ptr_.get(), in.get(), p.get(), bn_ctx.get());
  return bn_res;
}

void EcPoint::ToBytes(absl::Span<uint8_t> bytes) {
  BN_CTX_PTR bn_ctx(yacl::CheckNotNull(BN_CTX_new()));
  size_t length =
      EC_POINT_point2oct(group_ref_.get(), point_ptr_.get(),
                         POINT_CONVERSION_COMPRESSED, nullptr, 0, bn_ctx.get());

  YACL_ENFORCE(length == kEcPointCompressLength, "{}!={}", length,
               kEcPointCompressLength);

  std::vector<uint8_t> point_compress_bytes(length);
  EC_POINT_point2oct(group_ref_.get(), point_ptr_.get(),
                     POINT_CONVERSION_COMPRESSED,
                     reinterpret_cast<uint8_t*>(point_compress_bytes.data()),
                     point_compress_bytes.size(), bn_ctx.get());

  std::memcpy(bytes.data(), point_compress_bytes.data(), bytes.size());
}

void EcPoint::FromBytes(const EcGroup& ec_group, ByteContainerView bytes) {
  BN_CTX_PTR bn_ctx(yacl::CheckNotNull(BN_CTX_new()));

  int ret = EC_POINT_oct2point(ec_group.get(), point_ptr_.get(), bytes.data(),
                               bytes.size(), bn_ctx.get());
  YACL_ENFORCE(ret == 1);
}

EcPoint EcPoint::PointMul(const EcGroup& ec_group, const BigNum& bn) {
  BN_CTX_PTR bn_ctx(yacl::CheckNotNull(BN_CTX_new()));
  EcPoint ec_point(ec_group);
  int ret = EC_POINT_mul(ec_group.get(), ec_point.get(), nullptr,
                         point_ptr_.get(), bn.get(), bn_ctx.get());
  YACL_ENFORCE(ret == 1);
  return ec_point;
}

EcPoint EcPoint::PointAdd(const EcGroup& ec_group, const EcPoint& ec_point) {
  BN_CTX_PTR bn_ctx(yacl::CheckNotNull(BN_CTX_new()));
  EcPoint ec_point_out(ec_group);
  int ret = EC_POINT_add(ec_group.get(), ec_point_out.get(), point_ptr_.get(),
                         ec_point.get(), bn_ctx.get());
  YACL_ENFORCE(ret == 1);

  return ec_point_out;
}

EcPoint EcPoint::BasePointMul(const EcGroup& ec_group, const BigNum& bn) {
  BN_CTX_PTR bn_ctx(yacl::CheckNotNull(BN_CTX_new()));
  EcPoint ec_point(ec_group);

  int ret = EC_POINT_mul(ec_group.get(), ec_point.get(), bn.get(), nullptr,
                         nullptr, bn_ctx.get());

  YACL_ENFORCE(ret == 1);

  return ec_point;
}

}  // namespace yacl::crypto
