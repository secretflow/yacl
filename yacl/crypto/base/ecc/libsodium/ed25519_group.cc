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

#include "yacl/crypto/base/ecc/libsodium/ed25519_group.h"

#include <utility>

#include "sodium/crypto_core_ed25519.h"
#include "sodium/crypto_scalarmult_ed25519.h"

#include "yacl/crypto/base/ecc/ec_point.h"
#include "yacl/crypto/base/mpint/mp_int.h"
#include "yacl/crypto/base/mpint/type_traits.h"

namespace yacl::crypto::sodium {

#define RET_0(MP_ERR, ...) YACL_ENFORCE((MP_ERR) == 0, __VA_ARGS__)

Ed25519Group::Ed25519Group(const CurveMeta& meta, const CurveParam& param)
    : SodiumGroup(meta, param) {
  g_ = Ed25519Group::MulBase(1_mp);
  inf_ = Ed25519Group::Sub(g_, g_);
}

bool Ed25519Group::MPInt2Array(const MPInt& mp, Array32* buf) const {
  auto s = mp.Mod(param_.n);
  s.ToBytes(buf->data(), buf->size(), Endian::little);
  return s.IsPositive();
}

EcPoint Ed25519Group::GetGenerator() const { return g_; }

EcPoint Ed25519Group::Add(const EcPoint& p1, const EcPoint& p2) const {
  EcPoint r(std::in_place_type<Array32>);
  RET_0(crypto_core_ed25519_add(Cast(r), Cast(p1), Cast(p2)));
  return r;
}

void Ed25519Group::AddInplace(EcPoint* p1, const EcPoint& p2) const {
  RET_0(crypto_core_ed25519_add(Cast(*p1), Cast(*p1), Cast(p2)));
}

EcPoint Ed25519Group::Sub(const EcPoint& p1, const EcPoint& p2) const {
  EcPoint r(std::in_place_type<Array32>);
  RET_0(crypto_core_ed25519_sub(Cast(r), Cast(p1), Cast(p2)));
  return r;
}

void Ed25519Group::SubInplace(EcPoint* p1, const EcPoint& p2) const {
  RET_0(crypto_core_ed25519_sub(Cast(*p1), Cast(*p1), Cast(p2)));
}

EcPoint Ed25519Group::Double(const EcPoint& p) const { return Add(p, p); }

void Ed25519Group::DoubleInplace(EcPoint* p) const { AddInplace(p, *p); }

EcPoint Ed25519Group::MulBase(const MPInt& scalar) const {
  Array32 buf;
  if (!MPInt2Array(scalar, &buf)) {
    return inf_;
  };
  EcPoint r(std::in_place_type<Array32>);
  RET_0(crypto_scalarmult_ed25519_base_noclamp(Cast(r), buf.data()));
  return r;
}

EcPoint Ed25519Group::Mul(const EcPoint& point, const MPInt& scalar) const {
  Array32 buf;
  if (!MPInt2Array(scalar, &buf)) {
    return inf_;
  };
  EcPoint r(std::in_place_type<Array32>);
  RET_0(crypto_scalarmult_ed25519_noclamp(Cast(r), buf.data(), Cast(point)));
  return r;
}

void Ed25519Group::MulInplace(EcPoint* point, const MPInt& scalar) const {
  Array32 buf;
  if (!MPInt2Array(scalar, &buf)) {
    *point = inf_;
  } else {
    RET_0(crypto_scalarmult_ed25519_noclamp(Cast(*point), buf.data(),
                                            Cast(*point)));
  }
}

EcPoint Ed25519Group::MulDoubleBase(const MPInt& s1, const MPInt& s2,
                                    const EcPoint& p2) const {
  auto r = MulBase(s1);
  AddInplace(&r, Mul(p2, s2));
  return r;
}

EcPoint Ed25519Group::Negate(const EcPoint& point) const {
  EcPoint r = point;
  NegateInplace(&r);
  return r;
}

void Ed25519Group::NegateInplace(EcPoint* point) const {
  if (IsInfinity(*point)) {
    return;
  }

  auto* p = Cast(*point);
  p[31] ^= (1 << 7);
}

AffinePoint Ed25519Group::GetAffinePoint(const EcPoint& point) const {
  // https://www.rfc-editor.org/rfc/rfc8032.html#section-6  (recover_x)
  auto copy = point;
  auto* p = Cast(copy);
  uint8_t sign = p[31] >> 7;
  p[31] &= ((1 << 7) - 1);  // clear the bit of x
  MPInt y(0, 255);
  y.FromMagBytes({p, 32}, Endian::little);
  YACL_ENFORCE(y < param_.p, "illegal EcPoint (sign-{}, {})", sign, y);

  // constant d = -121665 * modp_inv(121666) % p
  static auto d =
      (-121665_mp).MulMod((121666_mp).InvertMod(param_.p), param_.p);
  auto y2 = y * y;
  auto x2 = (y2 - MPInt::_1_) * (d * y2 + MPInt::_1_).InvertMod(param_.p);

  if (x2.IsZero()) {
    YACL_ENFORCE(sign == 0, "invalid point (sign-{}, {})", sign, y);

    return {0_mp, y};
  }

  // Compute square root of x2
  auto tmp = param_.p + 3_mp;
  tmp >>= 3;
  auto x = x2.PowMod(tmp, param_.p);
  if (!(x * x).SubMod(x2, param_.p).IsZero()) {
    // Square root of -1
    static auto modp_sqrt_m1 =
        MPInt::_2_.PowMod((param_.p - 1_mp) >> 2, param_.p);
    MPInt::MulMod(x, modp_sqrt_m1, param_.p, &x);
  }

  YACL_ENFORCE((x * x).SubMod(x2, param_.p).IsZero(),
               "illegal EcPoint (sign-{}, {})", sign, y);

  if (x.GetBit(0) != sign) {
    x = param_.p - x;
  }
  return {x, y};
}

bool Ed25519Group::IsInCurveGroup(const EcPoint& point) const {
  // fixme: The answer should be true if point in small subgroup, buf current
  // returns false
  return IsInfinity(point) ||
         crypto_core_ed25519_is_valid_point(Cast(point)) == 1;
}

bool Ed25519Group::IsInfinity(const EcPoint& point) const {
  return PointEqual(inf_, point);
}

}  // namespace yacl::crypto::sodium
