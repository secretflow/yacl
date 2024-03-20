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

#include "yacl/crypto/ecc/libsodium/ed25519_group.h"

#include <utility>

#include "sodium/crypto_core_ed25519.h"
#include "sodium/crypto_scalarmult_ed25519.h"
#include "sodium/private/ed25519_ref10.h"

namespace yacl::crypto::sodium {

#define RET_0(MP_ERR, ...) YACL_ENFORCE((MP_ERR) == 0, __VA_ARGS__)

MPInt Fe25519ToMPInt(const fe25519& x) {
  Array32 buf;
  fe25519_tobytes(buf.data(), x);
  MPInt r(0, 255);
  r.FromMagBytes(buf, Endian::little);
  return r;
}

Ed25519Group::Ed25519Group(const CurveMeta& meta, const CurveParam& param)
    : SodiumGroup(meta, param) {
  static_assert(sizeof(ge25519_p2) <= sizeof(Array160));
  static_assert(sizeof(ge25519_p3) <= sizeof(Array160));
  static_assert(sizeof(ge25519_p1p1) <= sizeof(Array160));
  static_assert(sizeof(ge25519_precomp) <= sizeof(Array160));
  static_assert(sizeof(ge25519_cached) <= sizeof(Array160));

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
  ge25519_cached p2_cached;
  ge25519_p3_to_cached(&p2_cached, CastP3(p2));

  ge25519_p1p1 r_p1p1;
  ge25519_add(&r_p1p1, CastP3(p1), &p2_cached);

  EcPoint r(std::in_place_type<Array160>);
  ge25519_p1p1_to_p3(CastP3(r), &r_p1p1);

  // alternative api:
  // RET_0(crypto_core_ed25519_add(Cast(r), Cast(p1), Cast(p2)));
  return r;
}

void Ed25519Group::AddInplace(EcPoint* p1, const EcPoint& p2) const {
  ge25519_cached p2_cached;
  ge25519_p3_to_cached(&p2_cached, CastP3(p2));

  ge25519_p1p1 r_p1p1;
  ge25519_add(&r_p1p1, CastP3(*p1), &p2_cached);

  ge25519_p1p1_to_p3(CastP3(*p1), &r_p1p1);
}

EcPoint Ed25519Group::Sub(const EcPoint& p1, const EcPoint& p2) const {
  ge25519_cached p2_cached;
  ge25519_p3_to_cached(&p2_cached, CastP3(p2));

  ge25519_p1p1 r_p1p1;
  ge25519_sub(&r_p1p1, CastP3(p1), &p2_cached);

  EcPoint r(std::in_place_type<Array160>);
  ge25519_p1p1_to_p3(CastP3(r), &r_p1p1);

  // alternative api:
  // RET_0(crypto_core_ed25519_sub(Cast(r), Cast(p1), Cast(p2)));
  return r;
}

void Ed25519Group::SubInplace(EcPoint* p1, const EcPoint& p2) const {
  ge25519_cached p2_cached;
  ge25519_p3_to_cached(&p2_cached, CastP3(p2));

  ge25519_p1p1 r_p1p1;
  ge25519_sub(&r_p1p1, CastP3(*p1), &p2_cached);

  ge25519_p1p1_to_p3(CastP3(*p1), &r_p1p1);
}

EcPoint Ed25519Group::Double(const EcPoint& p) const { return Add(p, p); }

void Ed25519Group::DoubleInplace(EcPoint* p) const { AddInplace(p, *p); }

EcPoint Ed25519Group::MulBase(const MPInt& scalar) const {
  Array32 s;
  if (!MPInt2Array(scalar, &s)) {
    return inf_;
  };

  EcPoint r(std::in_place_type<Array160>);
  ge25519_scalarmult_base(CastP3(r), s.data());

  // alternative api:
  // RET_0(crypto_scalarmult_ed25519_base_noclamp(Cast(r), s.data()));
  return r;
}

EcPoint Ed25519Group::Mul(const EcPoint& point, const MPInt& scalar) const {
  Array32 s;
  if (!MPInt2Array(scalar, &s) || IsInfinity(point)) {
    return inf_;
  };

  EcPoint r(std::in_place_type<Array160>);
  ge25519_scalarmult(CastP3(r), s.data(), CastP3(point));

  // alternative api:
  //  RET_0(crypto_scalarmult_ed25519_noclamp(Cast(r), s.data(), Cast(point)));
  return r;
}

void Ed25519Group::MulInplace(EcPoint* point, const MPInt& scalar) const {
  Array32 s;
  if (!MPInt2Array(scalar, &s) || IsInfinity(*point)) {
    *point = inf_;
  } else {
    ge25519_scalarmult(CastP3(*point), s.data(), CastP3(*point));
  }
}

EcPoint Ed25519Group::MulDoubleBase(const MPInt& s1, const MPInt& s2,
                                    const EcPoint& p2) const {
  auto r = MulBase(s1);
  AddInplace(&r, Mul(p2, s2));
  return r;
}

EcPoint Ed25519Group::Negate(const EcPoint& point) const {
  if (IsInfinity(point)) {
    return point;
  }

  auto p3 = CastP3(point);
  EcPoint r(std::in_place_type<Array160>);
  auto r3 = CastP3(r);

  fe25519_copy(r3->X, p3->X);
  fe25519_neg(r3->Y, p3->Y);
  fe25519_neg(r3->Z, p3->Z);
  fe25519_copy(r3->T, p3->T);
  return r;
}

void Ed25519Group::NegateInplace(EcPoint* point) const {
  if (IsInfinity(*point)) {
    return;
  }

  auto* p3 = CastP3(*point);
  fe25519_neg(p3->Y, p3->Y);
  fe25519_neg(p3->Z, p3->Z);
}

AffinePoint Ed25519Group::GetAffinePoint(const EcPoint& point) const {
  const auto* p3 = CastP3(point);
  fe25519 recip;
  fe25519 x;
  fe25519 y;

  fe25519_invert(recip, p3->Z);
  fe25519_mul(x, p3->X, recip);
  fe25519_mul(y, p3->Y, recip);

  return {Fe25519ToMPInt(x), Fe25519ToMPInt(y)};
}

bool Ed25519Group::IsInCurveGroup(const EcPoint& point) const {
  return IsInfinity(point) || ge25519_is_on_curve(CastP3(point)) == 1;
}

bool Ed25519Group::IsInfinity(const EcPoint& point) const {
  return fe25519_iszero(CastP3(point)->X) != 0 ||
         fe25519_iszero(CastP3(point)->Z) != 0;
}

}  // namespace yacl::crypto::sodium
