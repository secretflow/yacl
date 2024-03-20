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

#include "yacl/crypto/ecc/openssl/openssl_group.h"

#include <vector>

#include "yacl/crypto/hash/blake3.h"
#include "yacl/crypto/hash/ssl_hash.h"
#include "yacl/crypto/openssl_wrappers.h"
#include "yacl/utils/scope_guard.h"
#include "yacl/utils/spi/type_traits.h"

namespace yacl::crypto::openssl {

static constexpr size_t kHashToCurveCounterGuard = 100;

thread_local UniqueBnCtx OpensslGroup::ctx_ = UniqueBnCtx(BN_CTX_new());

UniqueBn Mp2Bn(const MPInt &mp) {
  bool is_neg = mp.IsNegative();

  UniqueBn res;
  if (mp.BitCount() <= sizeof(BN_ULONG) * CHAR_BIT) {
    res = UniqueBn(BN_new());
    OSSL_RET_1(BN_set_word(res.get(), mp.Get<BN_ULONG>()));
  } else {
    constexpr int MAX_NUM_BYTE = 1024;
    unsigned char buf[MAX_NUM_BYTE];
    auto buf_len = mp.ToMagBytes(buf, MAX_NUM_BYTE, Endian::little);
    res = UniqueBn(BN_lebin2bn(buf, buf_len, nullptr));
  }

  if (is_neg) {  // mpp is negative
    BN_set_negative(res.get(), true);
  }

  return res;
}

MPInt Bn2Mp(const BIGNUM *bn) {
  CheckNotNull(bn);
  auto buf_len = BN_num_bytes(bn);
  unsigned char buf[buf_len];
  YACL_ENFORCE(BN_bn2lebinpad(bn, buf, buf_len) >= 0);

  MPInt mp;
  mp.FromMagBytes({buf, static_cast<size_t>(buf_len)}, Endian::little);

  if (BN_is_negative(bn)) {
    mp.NegateInplace();
  }
  return mp;
}

AnyPtr WrapOpensslPoint(EC_POINT *point) {
  return {point,
          [](void *p) { EC_POINT_free(reinterpret_cast<EC_POINT *>(p)); }};
}

OpensslGroup::OpensslGroup(const CurveMeta &meta, UniqueEcGroup group)
    : EcGroupSketch(meta), group_(std::move(group)), field_p_(BN_new()) {
  generator_ = WrapOpensslPoint(
      EC_POINT_dup(EC_GROUP_get0_generator(group_.get()), group_.get()));
  order_ = Bn2Mp(EC_GROUP_get0_order(group_.get()));
  cofactor_ = Bn2Mp(EC_GROUP_get0_cofactor(group_.get()));
  OSSL_RET_1(EC_GROUP_get_curve(group_.get(), field_p_.get(), nullptr, nullptr,
                                ctx_.get()));
}

AnyPtr OpensslGroup::MakeOpensslPoint() const {
  return WrapOpensslPoint(EC_POINT_new(group_.get()));
}

MPInt OpensslGroup::GetCofactor() const { return cofactor_; }

MPInt OpensslGroup::GetField() const { return Bn2Mp(field_p_.get()); }

MPInt OpensslGroup::GetOrder() const { return order_; }

EcPoint OpensslGroup::GetGenerator() const { return generator_; }

std::string OpensslGroup::ToString() const { return GetCurveName(); }

EcPoint OpensslGroup::Add(const EcPoint &p1, const EcPoint &p2) const {
  auto res = MakeOpensslPoint();
  OSSL_RET_1(EC_POINT_add(group_.get(), CastAny<EC_POINT>(res),
                          CastAny<EC_POINT>(p1), CastAny<EC_POINT>(p2),
                          ctx_.get()));
  return res;
}

void OpensslGroup::AddInplace(EcPoint *p1, const EcPoint &p2) const {
  OSSL_RET_1(EC_POINT_add(group_.get(), CastAny<EC_POINT>(p1),
                          CastAny<EC_POINT>(p1), CastAny<EC_POINT>(p2),
                          ctx_.get()));
}

EcPoint OpensslGroup::Double(const EcPoint &p) const {
  auto res = MakeOpensslPoint();
  OSSL_RET_1(EC_POINT_dbl(group_.get(), CastAny<EC_POINT>(res),
                          CastAny<EC_POINT>(p), ctx_.get()));
  return res;
}

void OpensslGroup::DoubleInplace(EcPoint *p) const {
  OSSL_RET_1(EC_POINT_dbl(group_.get(), CastAny<EC_POINT>(p),
                          CastAny<EC_POINT>(p), ctx_.get()));
}

EcPoint OpensslGroup::MulBase(const MPInt &scalar) const {
  auto res = MakeOpensslPoint();
  auto s = Mp2Bn(scalar);
  // EC_POINT_mul has random memory leaks, be careful.
  // See UT for demo code.
  // We tested openssl 3.1.0, it still leaks.
  OSSL_RET_1(EC_POINT_mul(group_.get(), CastAny<EC_POINT>(res), s.get(),
                          nullptr, nullptr, ctx_.get()));
  return res;
}

EcPoint OpensslGroup::Mul(const EcPoint &point, const MPInt &scalar) const {
  auto res = MakeOpensslPoint();
  auto s = Mp2Bn(scalar);
  OSSL_RET_1(EC_POINT_mul(group_.get(), CastAny<EC_POINT>(res), nullptr,
                          CastAny<EC_POINT>(point), s.get(), ctx_.get()));
  return res;
}

void OpensslGroup::MulInplace(EcPoint *point, const MPInt &scalar) const {
  auto s = Mp2Bn(scalar);
  OSSL_RET_1(EC_POINT_mul(group_.get(), CastAny<EC_POINT>(point), nullptr,
                          CastAny<EC_POINT>(point), s.get(), ctx_.get()));
}

EcPoint OpensslGroup::MulDoubleBase(const MPInt &s1, const MPInt &s2,
                                    const EcPoint &p2) const {
  auto res = MakeOpensslPoint();
  auto bn1 = Mp2Bn(s1);
  auto bn2 = Mp2Bn(s2);
  OSSL_RET_1(EC_POINT_mul(group_.get(), CastAny<EC_POINT>(res), bn1.get(),
                          CastAny<EC_POINT>(p2), bn2.get(), ctx_.get()));
  return res;
}

EcPoint OpensslGroup::Negate(const EcPoint &point) const {
  auto res =
      WrapOpensslPoint(EC_POINT_dup(CastAny<EC_POINT>(point), group_.get()));
  OSSL_RET_1(EC_POINT_invert(group_.get(), CastAny<EC_POINT>(res), ctx_.get()));
  return res;
}

void OpensslGroup::NegateInplace(EcPoint *point) const {
  OSSL_RET_1(
      EC_POINT_invert(group_.get(), CastAny<EC_POINT>(point), ctx_.get()));
}

EcPoint OpensslGroup::CopyPoint(const EcPoint &point) const {
  if (std::holds_alternative<AnyPtr>(point)) {
    return WrapOpensslPoint(
        EC_POINT_dup(CastAny<EC_POINT>(point), group_.get()));
  }

  if (std::holds_alternative<AffinePoint>(point)) {
    auto p = std::get<AffinePoint>(point);
    // Convert AffinePoint to EC_POINT
    auto x = Mp2Bn(p.x);
    auto y = Mp2Bn(p.y);
    auto r = MakeOpensslPoint();
    OSSL_RET_1(EC_POINT_set_affine_coordinates(
        group_.get(), CastAny<EC_POINT>(r), x.get(), y.get(), ctx_.get()));
    return r;
  }

  YACL_THROW("Unsupported EcPoint type {}", point.index());
}

AffinePoint OpensslGroup::GetAffinePoint(const EcPoint &point) const {
  if (IsInfinity(point)) {
    return {};
  }

  auto x = UniqueBn(BN_new());
  auto y = UniqueBn(BN_new());
  OSSL_RET_1(EC_POINT_get_affine_coordinates(
      group_.get(), CastAny<EC_POINT>(point), x.get(), y.get(), ctx_.get()));
  return {Bn2Mp(x.get()), Bn2Mp(y.get())};
}

uint64_t OpensslGroup::GetSerializeLength(PointOctetFormat format) const {
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

  size_t len = EC_POINT_point2oct(group_.get(), CastAny<EC_POINT>(generator_),
                                  f, nullptr, 0, ctx_.get());
  YACL_ENFORCE(len != 0, "calc serialize point size, openssl returns 0");
  return len;
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

  size_t len = EC_POINT_point2oct(group_.get(), CastAny<EC_POINT>(point), f,
                                  nullptr, 0, ctx_.get());
  YACL_ENFORCE(len != 0, "calc serialize point size, openssl returns 0");
  buf->resize(len);

  len = EC_POINT_point2oct(group_.get(), CastAny<EC_POINT>(point), f,
                           buf->data<unsigned char>(), len, ctx_.get());
  YACL_ENFORCE(len != 0, "serialize point to buf fail, openssl returns 0");
}

void OpensslGroup::SerializePoint(const EcPoint &point, PointOctetFormat format,
                                  uint8_t *buf, uint64_t buf_size) const {
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

  size_t len = EC_POINT_point2oct(group_.get(), CastAny<EC_POINT>(point), f,
                                  nullptr, 0, ctx_.get());
  YACL_ENFORCE(len != 0, "calc serialize point size, openssl returns 0");
  YACL_ENFORCE(buf_size >= static_cast<uint64_t>(len),
               "buf size is small than needed {}", len);
  len = EC_POINT_point2oct(group_.get(), CastAny<EC_POINT>(point), f, buf, len,
                           ctx_.get());
  if (buf_size > static_cast<uint64_t>(len)) {
    std::memset(buf + len, 0, buf_size - len);
  }
}

EcPoint OpensslGroup::DeserializePoint(ByteContainerView buf,
                                       PointOctetFormat) const {
  auto p = MakeOpensslPoint();
  // buf[0] == 0 indicate it's a infinity point, will fail if input len != 1
  OSSL_RET_1(EC_POINT_oct2point(group_.get(), CastAny<EC_POINT>(p), buf.data(),
                                !buf.empty() && buf[0] != 0 ? buf.length() : 1,
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
      YACL_THROW("Openssl does not support TryAndRehash_SHA3 strategy now");
      break;
    case HashToCurveStrategy::TryAndRehash_SM:
      hash_algorithm = HashAlgorithm::SM3;
      break;
    case HashToCurveStrategy::TryAndRehash_BLAKE3:
    case HashToCurveStrategy::Autonomous:
      hash_algorithm = HashAlgorithm::BLAKE3;
      break;
    default:
      YACL_THROW("Openssl only supports TryAndRehash strategy now. select={}",
                 (int)strategy);
  }

  auto point = MakeOpensslPoint();

  std::vector<uint8_t> buf;
  if (hash_algorithm != HashAlgorithm::BLAKE3) {
    buf = SslHash(hash_algorithm).Update(str).CumulativeHash();
  } else {
    buf = Blake3Hash((bits + 7) / 8).Update(str).CumulativeHash();
  }
  auto bn = UniqueBn(BN_new());
  for (size_t t = 0; t < kHashToCurveCounterGuard; ++t) {
    // hash value to BN
    YACL_ENFORCE(BN_bin2bn(buf.data(), buf.size(), bn.get()) != nullptr,
                 "Convert hash value to bignumber fail");
    OSSL_RET_1(BN_nnmod(bn.get(), bn.get(), field_p_.get(), ctx_.get()),
               "hash-to-curve: bn mod p fail");

    // check BN on the curve
    int ret = EC_POINT_set_compressed_coordinates(
        group_.get(), CastAny<EC_POINT>(point), bn.get(), 0, ctx_.get());
    if (ret == 1) {
      return point;
    }

    // do rehash
    if (hash_algorithm != HashAlgorithm::BLAKE3) {
      buf = SslHash(hash_algorithm).Update(buf).CumulativeHash();
    } else {
      buf = Blake3Hash((bits + 7) / 8).Update(buf).CumulativeHash();
    }
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
  YACL_ENFORCE(BN_bn2lebinpad(bn, reinterpret_cast<unsigned char *>(buf), len) >
               0);
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
  thread_local UniqueBn x(BN_new());
  thread_local UniqueBn y(BN_new());
  // You cannot use projective coordinates here because point expression is not
  // unique
  OSSL_RET_1(EC_POINT_get_affine_coordinates(
      group_.get(), CastAny<EC_POINT>(point), x.get(), y.get(), ctx_.get()));
  return HashBn(x.get()) + BN_is_odd(y.get());
}

bool OpensslGroup::PointEqual(const EcPoint &p1, const EcPoint &p2) const {
  auto res = EC_POINT_cmp(group_.get(), CastAny<EC_POINT>(p1),
                          CastAny<EC_POINT>(p2), ctx_.get());
  YACL_ENFORCE(res >= 0);
  return res == 0;
}

bool OpensslGroup::IsInCurveGroup(const EcPoint &point) const {
  // EC_POINT_is_on_curve returns 1 if the point is on the curve, 0 if not, or
  // -1 on error.
  auto ret =
      EC_POINT_is_on_curve(group_.get(), CastAny<EC_POINT>(point), ctx_.get());
  YACL_ENFORCE(ret >= 0, "calc point is on curve fail, err={}", ret);
  return ret == 1 || IsInfinity(point);
}

bool OpensslGroup::IsInfinity(const EcPoint &point) const {
  return EC_POINT_is_at_infinity(group_.get(), CastAny<EC_POINT>(point)) == 1;
}

}  // namespace yacl::crypto::openssl
