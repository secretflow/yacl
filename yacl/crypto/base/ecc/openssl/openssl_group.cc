// Copyright 2023 Ant Group Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "yacl/crypto/base/ecc/openssl/openssl_group.h"

#include "yacl/crypto/base/hash/ssl_hash.h"
#include "yacl/utils/scope_guard.h"

namespace yacl::crypto::openssl {

static constexpr size_t kHashToCurveCounterGuard = 100;

thread_local BN_CTX_PTR OpensslGroup::ctx_ = BN_CTX_PTR(BN_CTX_new());

//--- helper tools ---//

#define SSL_RET_1(MP_ERR, ...) YACL_ENFORCE_EQ((MP_ERR), 1, __VA_ARGS__)
#define SSL_RET_N(MP_ERR, ...) YACL_ENFORCE_GE((MP_ERR), 0, __VA_ARGS__)
#define SSL_RET_ZP(MP_ERR, ...) YACL_ENFORCE_GT((MP_ERR), 0, __VA_ARGS__)

BIGNUM_PTR Mp2Bn(const MPInt &mp) {
  const MPInt *mpp = &mp;
  MPInt tmp;
  if (mp.IsNegative()) {
    mp.Negate(&tmp);
    mpp = &tmp;
  }

  BIGNUM_PTR res;
  if (mpp->BitCount() <= sizeof(BN_ULONG) * 8) {
    res = BIGNUM_PTR(BN_new());
    SSL_RET_1(BN_set_word(res.get(), mpp->Get<BN_ULONG>()));
  } else {
    constexpr int MAX_NUM_BYTE = 1024;
    unsigned char buf[MAX_NUM_BYTE];
    YACL_ENFORCE(mpp->BitCount() < MAX_NUM_BYTE,
                 "Cannot convert mpint [{}], too big", mp.ToString());
    mpp->ToBytes(buf, MAX_NUM_BYTE, Endian::little);
    res = BIGNUM_PTR(BN_lebin2bn(buf, MAX_NUM_BYTE, nullptr));
  }

  if (mpp == &tmp) {  // mpp is negative
    BN_set_negative(res.get(), true);
  }

  return res;
}

MPInt Bn2Mp(const BIGNUM *bn) {
  CheckNotNull(bn);
  MPInt mp;
  auto *hex_str = BN_bn2hex(bn);
  ON_SCOPE_EXIT([&] { OPENSSL_free(hex_str); });
  mp.Set(hex_str, 16);
  return mp;
}

const EC_POINT *Cast(const EcPoint &p) {
  YACL_ENFORCE(
      std::holds_alternative<AnyPointPtr>(p),
      "Unsupported EcPoint type, expected AnyPointPtr, real type index is {}",
      p.index());

  return std::get<AnyPointPtr>(p).get<EC_POINT>();
}

EC_POINT *Cast(EcPoint *p) {
  CheckNotNull(p);
  YACL_ENFORCE(
      std::holds_alternative<AnyPointPtr>(*p),
      "Unsupported EcPoint type, expected AnyPointPtr, real type index is {}",
      p->index());

  return std::get<AnyPointPtr>(*p).get<EC_POINT>();
}

EC_POINT *Cast(AnyPointPtr &ptr) { return ptr.get<EC_POINT>(); }

AnyPointPtr WrapOpensslPoint(EC_POINT *point) {
  return {point,
          [](void *p) { EC_POINT_free(reinterpret_cast<EC_POINT *>(p)); }};
}

OpensslGroup::OpensslGroup(const CurveMeta &meta, EC_GROUP_PTR group)
    : EcGroupSketch(meta), group_(std::move(group)), field_p_(BN_new()) {
  SSL_RET_1(EC_GROUP_get_curve(group_.get(), field_p_.get(), nullptr, nullptr,
                               ctx_.get()));
  SSL_RET_1(EC_GROUP_precompute_mult(group_.get(), ctx_.get()));
}

AnyPointPtr OpensslGroup::MakeOpensslPoint() const {
  return WrapOpensslPoint(EC_POINT_new(group_.get()));
}

MPInt OpensslGroup::GetCofactor() const {
  static MPInt cache = Bn2Mp(EC_GROUP_get0_cofactor(group_.get()));
  return cache;
}

MPInt OpensslGroup::GetField() const {
  static MPInt cache = Bn2Mp(field_p_.get());
  return cache;
}

MPInt OpensslGroup::GetOrder() const {
  static MPInt cache = Bn2Mp(EC_GROUP_get0_order(group_.get()));
  return cache;
}

EcPoint OpensslGroup::GetGenerator() const {
  static EcPoint cache = WrapOpensslPoint(
      EC_POINT_dup(EC_GROUP_get0_generator(group_.get()), group_.get()));
  return cache;
}

std::string OpensslGroup::ToString() { return GetCurveName(); }

EcPoint OpensslGroup::Add(const EcPoint &p1, const EcPoint &p2) const {
  auto res = MakeOpensslPoint();
  SSL_RET_1(
      EC_POINT_add(group_.get(), Cast(res), Cast(p1), Cast(p2), ctx_.get()));
  return res;
}

void OpensslGroup::AddInplace(EcPoint *p1, const EcPoint &p2) const {
  SSL_RET_1(
      EC_POINT_add(group_.get(), Cast(p1), Cast(p1), Cast(p2), ctx_.get()));
}

EcPoint OpensslGroup::Double(const EcPoint &p) const {
  auto res = MakeOpensslPoint();
  SSL_RET_1(EC_POINT_dbl(group_.get(), Cast(res), Cast(p), ctx_.get()));
  return res;
}

void OpensslGroup::DoubleInplace(EcPoint *p) const {
  SSL_RET_1(EC_POINT_dbl(group_.get(), Cast(p), Cast(p), ctx_.get()));
}

EcPoint OpensslGroup::MulBase(const MPInt &scalar) const {
  auto res = MakeOpensslPoint();
  auto s = Mp2Bn(scalar);
  SSL_RET_1(EC_POINTs_mul(group_.get(), Cast(res), s.get(), 0, nullptr, nullptr,
                          ctx_.get()));
  return res;
}

EcPoint OpensslGroup::Mul(const EcPoint &point, const MPInt &scalar) const {
  auto res = MakeOpensslPoint();
  auto s = Mp2Bn(scalar);
  SSL_RET_1(EC_POINT_mul(group_.get(), Cast(res), nullptr, Cast(point), s.get(),
                         ctx_.get()));
  return res;
}

void OpensslGroup::MulInplace(EcPoint *point, const MPInt &scalar) const {
  auto s = Mp2Bn(scalar);
  SSL_RET_1(EC_POINT_mul(group_.get(), Cast(point), nullptr, Cast(point),
                         s.get(), ctx_.get()));
}

EcPoint OpensslGroup::MulDoubleBase(const MPInt &s1, const MPInt &s2,
                                    const EcPoint &p2) const {
  auto res = MakeOpensslPoint();
  auto bn1 = Mp2Bn(s1);
  auto bn2 = Mp2Bn(s2);
  SSL_RET_1(EC_POINT_mul(group_.get(), Cast(res), bn1.get(), Cast(p2),
                         bn2.get(), ctx_.get()));
  return res;
}

EcPoint OpensslGroup::Negate(const EcPoint &point) const {
  auto res = WrapOpensslPoint(EC_POINT_dup(Cast(point), group_.get()));
  SSL_RET_1(EC_POINT_invert(group_.get(), Cast(res), ctx_.get()));
  return res;
}

void OpensslGroup::NegateInplace(EcPoint *point) const {
  SSL_RET_1(EC_POINT_invert(group_.get(), Cast(point), ctx_.get()));
}

AffinePoint OpensslGroup::GetAffinePoint(const EcPoint &point) const {
  if (IsInfinity(point)) {
    return {};
  }

  auto x = BIGNUM_PTR(BN_new());
  auto y = BIGNUM_PTR(BN_new());
  SSL_RET_1(EC_POINT_get_affine_coordinates(group_.get(), Cast(point), x.get(),
                                            y.get(), ctx_.get()));
  return {Bn2Mp(x.get()), Bn2Mp(y.get())};
}

AnyPointPtr OpensslGroup::GetSslPoint(const AffinePoint &p) const {
  auto point = MakeOpensslPoint();
  // Convert AffinePoint to EC_POINT
  auto x = Mp2Bn(p.x);
  auto y = Mp2Bn(p.y);
  SSL_RET_1(EC_POINT_set_affine_coordinates(group_.get(), Cast(point), x.get(),
                                            y.get(), ctx_.get()));
  return point;
}

Buffer OpensslGroup::SerializePoint(const EcPoint &point,
                                    PointOctetFormat format) const {
  Buffer buf;
  SerializePoint(point, format, &buf);
  return buf;
}

void OpensslGroup::SerializePoint(const EcPoint &point, PointOctetFormat format,
                                  Buffer *buf) const {
  point_conversion_form_t f;
  switch (format) {
    case PointOctetFormat::X962Uncompressed:
      f = POINT_CONVERSION_UNCOMPRESSED;
      break;
    case PointOctetFormat::X962Hybrid:
      f = POINT_CONVERSION_HYBRID;
      break;
    default:
      f = POINT_CONVERSION_COMPRESSED;
      break;
  }

  int64_t len =
      EC_POINT_point2oct(group_.get(), Cast(point), f, nullptr, 0, ctx_.get());
  SSL_RET_ZP(len, "calc serialize point size, openssl returns 0");
  buf->resize(len);

  len = EC_POINT_point2oct(group_.get(), Cast(point), f,
                           buf->data<unsigned char>(), len, ctx_.get());
  SSL_RET_ZP(len, "serialize point to buf fail, openssl returns 0");
}

EcPoint OpensslGroup::DeserializePoint(ByteContainerView buf,
                                       PointOctetFormat format) const {
  auto p = MakeOpensslPoint();
  SSL_RET_1(EC_POINT_oct2point(group_.get(), Cast(p), buf.data(), buf.length(),
                               ctx_.get()));
  return p;
}

EcPoint OpensslGroup::HashToCurve(HashToCurveStrategy strategy,
                                  std::string_view str) const {
  auto bits = EC_GROUP_order_bits(group_.get());
  HashAlgorithm hash_algorithm;
  switch (strategy) {
    case HashToCurveStrategy::TryAndRehash_SHA2:
      if (bits <= 224) {
        hash_algorithm = HashAlgorithm::SHA224;
      } else if (bits <= 256) {
        hash_algorithm = HashAlgorithm::SHA256;
      } else if (bits <= 384) {
        hash_algorithm = HashAlgorithm::SHA384;
      } else {
        hash_algorithm = HashAlgorithm::SHA512;
      }
      break;
    case HashToCurveStrategy::TryAndRehash_SHA3:
      YACL_THROW("Openssl lib do not support TryAndRehash_SHA3 strategy now");
      break;
    case HashToCurveStrategy::TryAndRehash_SM:
      hash_algorithm = HashAlgorithm::SM3;
      break;
    default:
      YACL_THROW(
          "Openssl lib only support TryAndRehash strategy now. select={}",
          (int)strategy);
  }

  auto point = MakeOpensslPoint();
  auto buf = SslHash(hash_algorithm).Update(str).CumulativeHash();
  auto bn = BIGNUM_PTR(BN_new());
  for (size_t t = 0; t < kHashToCurveCounterGuard; ++t) {
    // hash value to BN
    YACL_ENFORCE(BN_bin2bn(buf.data(), buf.size(), bn.get()) != nullptr,
                 "Convert hash value to bignumber fail");
    SSL_RET_1(BN_nnmod(bn.get(), bn.get(), field_p_.get(), ctx_.get()),
              "hash-to-curve: bn mod p fail");

    // check BN on the curve
    int ret = EC_POINT_set_compressed_coordinates(group_.get(), Cast(point),
                                                  bn.get(), 0, ctx_.get());
    if (ret == 1) {
      return point;
    }

    // do rehash
    buf = SslHash(hash_algorithm).Update(buf).CumulativeHash();
  }

  YACL_THROW("Openssl HashToCurve exceed max loop({})",
             kHashToCurveCounterGuard);
}

namespace {
size_t HashBn(const BIGNUM *bn) {
  if (bn == nullptr) {
    return 0;
  }
  int len = BN_num_bytes(bn);
  char buf[len];
  SSL_RET_ZP(BN_bn2lebinpad(bn, reinterpret_cast<unsigned char *>(buf), len));
  return std::hash<std::string_view>{}({buf, static_cast<size_t>(len)});
}
}  // namespace

// Hash point under projective coordinate is very slow. How to improve?
size_t OpensslGroup::HashPoint(const EcPoint &point) const {
  if (IsInfinity(point)) {
    return 0;
  }

  // 1. `thread_local` variables are also static variables, we can reuse these
  // variables to avoid frequent memory allocation.
  // 2. We declare variables as thread_local to ensure thread safety
  thread_local BIGNUM_PTR x(BN_new());
  thread_local BIGNUM_PTR y(BN_new());
  // You cannot use projective coordinates here because point expression is not
  // unique
  SSL_RET_1(EC_POINT_get_affine_coordinates(group_.get(), Cast(point), x.get(),
                                            y.get(), ctx_.get()));
  return HashBn(x.get()) + BN_is_odd(y.get());
}

bool OpensslGroup::PointEqual(const EcPoint &p1, const EcPoint &p2) const {
  auto res = EC_POINT_cmp(group_.get(), Cast(p1), Cast(p2), ctx_.get());
  SSL_RET_N(res);
  return res == 0;
}

bool OpensslGroup::IsInCurveGroup(const EcPoint &point) const {
  auto ret = EC_POINT_is_on_curve(group_.get(), Cast(point), ctx_.get());
  SSL_RET_N(ret, "calc point is on curve fail, err={}", ret);
  return ret == 1 || IsInfinity(point);
}

bool OpensslGroup::IsInfinity(const EcPoint &point) const {
  return EC_POINT_is_at_infinity(group_.get(), Cast(point)) == 1;
}

}  // namespace yacl::crypto::openssl
