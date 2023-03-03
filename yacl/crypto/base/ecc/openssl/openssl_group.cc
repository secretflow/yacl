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

#include "yacl/utils/scope_guard.h"

namespace yacl::crypto::openssl {

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
    BN_set_word(res.get(), mpp->Get<BN_ULONG>());
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

EC_POINT *Cast(const AnyPointPtr &ptr) { return ptr.get<EC_POINT>(); }

AnyPointPtr WrapOpensslPoint(EC_POINT *point) {
  static auto point_deleter = [](void *p) {
    if (p == nullptr) {
      return;
    }

    EC_POINT_free(reinterpret_cast<EC_POINT *>(p));
  };

  return AnyPointPtr(point, point_deleter);
}

AnyPointPtr OpensslGroup::MakeOpensslPoint() const {
  return WrapOpensslPoint(EC_POINT_new(group_.get()));
}

MPInt OpensslGroup::GetCofactor() const {
  return Bn2Mp(EC_GROUP_get0_cofactor(group_.get()));
}

MPInt OpensslGroup::GetField() const {
  auto bn_p = BIGNUM_PTR(BN_new());
  SSL_RET_1(EC_GROUP_get_curve(group_.get(), bn_p.get(), nullptr, nullptr,
                               ctx_.get()));
  return Bn2Mp(bn_p.get());
}

MPInt OpensslGroup::GetOrder() const {
  return Bn2Mp(EC_GROUP_get0_order(group_.get()));
}

EcPoint OpensslGroup::GetGenerator() const {
  return WrapOpensslPoint(
      EC_POINT_dup(EC_GROUP_get0_generator(group_.get()), group_.get()));
}

std::string OpensslGroup::ToString() { return GetCurveName(); }

EcPoint OpensslGroup::Add(const EcPoint &p1, const EcPoint &p2) const {
  auto res = MakeOpensslPoint();
  SSL_RET_1(
      EC_POINT_add(group_.get(), Cast(res), Cast(p1), Cast(p2), ctx_.get()));
  return res;
}

EcPoint OpensslGroup::Sub(const EcPoint &p1, const EcPoint &p2) const {
  return Add(p1, Negate(p2));
}

EcPoint OpensslGroup::Double(const EcPoint &p) const {
  auto res = MakeOpensslPoint();
  SSL_RET_1(EC_POINT_dbl(group_.get(), Cast(res), Cast(p), ctx_.get()));
  return res;
}

EcPoint OpensslGroup::MulBase(const MPInt &scalar) const {
  auto res = MakeOpensslPoint();
  auto s = Mp2Bn(scalar);
  SSL_RET_1(EC_POINTs_mul(group_.get(), Cast(res), s.get(), 0, nullptr, nullptr,
                          ctx_.get()));
  return res;
}

EcPoint OpensslGroup::Mul(const MPInt &scalar, const EcPoint &point) const {
  auto res = MakeOpensslPoint();
  auto s = Mp2Bn(scalar);
  SSL_RET_1(EC_POINT_mul(group_.get(), Cast(res), nullptr, Cast(point), s.get(),
                         ctx_.get()));
  return res;
}

EcPoint OpensslGroup::MulDoubleBase(const MPInt &scalar1, const EcPoint &point1,
                                    const MPInt &scalar2) const {
  auto res = MakeOpensslPoint();
  auto s1 = Mp2Bn(scalar1);
  auto s2 = Mp2Bn(scalar2);
  SSL_RET_1(EC_POINT_mul(group_.get(), Cast(res), s2.get(), Cast(point1),
                         s1.get(), ctx_.get()));
  return res;
}

EcPoint OpensslGroup::Div(const EcPoint &point, const MPInt &scalar) const {
  YACL_ENFORCE(!scalar.IsZero(), "Ecc point can not div by zero!");

  if (scalar.IsPositive()) {
    return Mul(scalar.InvertMod(GetOrder()), point);
  }

  auto res = Mul(scalar.Abs().InvertMod(GetOrder()), point);
  return Negate(res);
}

EcPoint OpensslGroup::Negate(const EcPoint &point) const {
  auto res = WrapOpensslPoint(EC_POINT_dup(Cast(point), group_.get()));
  SSL_RET_1(EC_POINT_invert(group_.get(), Cast(res), ctx_.get()));
  return res;
}

AffinePoint OpensslGroup::GetAffinePoint(const EcPoint &point) const {
  auto x = BIGNUM_PTR(BN_new());
  auto y = BIGNUM_PTR(BN_new());
  SSL_RET_1(EC_POINT_get_affine_coordinates(group_.get(), Cast(point), x.get(),
                                            y.get(), ctx_.get()));
  return AffinePoint(Bn2Mp(x.get()), Bn2Mp(y.get()));
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
  // TODO hash to curve
  return yacl::crypto::EcPoint();
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
