// Copyright 2024 Ant Group Co., Ltd.
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

#include "yacl/crypto/ecc/lib25519/ed25519_group.h"

namespace yacl::crypto::lib25519 {

MPInt Fe25519ToMPInt(const fe25519& x) {
  // TODO: whether to freeze x first?
  MPInt r(0, 255);
  r.FromMagBytes(yacl::ByteContainerView(&x, 32), Endian::little);
  return r;
}

Ed25519Group::Ed25519Group(const CurveMeta& meta, const CurveParam& param)
    : Lib25519Group(meta, param) {
  static_assert(sizeof(ge25519_p3) <= sizeof(Array128));

  g_ = Ed25519Group::MulBase(1_mp);
  inf_ = Ed25519Group::Sub(g_, g_);
}

bool Ed25519Group::MPInt2Scalar(const MPInt& mp, sc25519* scalar) const {
  auto s = mp.Mod(param_.n);
  Array32 buf;
  s.ToBytes(buf.data(), 32, Endian::little);
  sc25519_from32bytes(scalar, buf.data());
  return s.IsPositive();
}

EcPoint Ed25519Group::GetGenerator() const { return g_; }

EcPoint Ed25519Group::Add(const EcPoint& p1, const EcPoint& p2) const {
  EcPoint r(std::in_place_type<Array128>);
  ge25519_add(CastP3(r), CastP3(p1), CastP3(p2));

  return r;
}

void Ed25519Group::AddInplace(EcPoint* p1, const EcPoint& p2) const {
  ge25519_add(CastP3(*p1), CastP3(*p1), CastP3(p2));
}

EcPoint Ed25519Group::Sub(const EcPoint& p1, const EcPoint& p2) const {
  EcPoint r(std::in_place_type<Array128>);
  ge25519_sub(CastP3(r), CastP3(p1), CastP3(p2));

  return r;
}

void Ed25519Group::SubInplace(EcPoint* p1, const EcPoint& p2) const {
  ge25519_sub(CastP3(*p1), CastP3(*p1), CastP3(p2));
}

EcPoint Ed25519Group::Double(const EcPoint& p) const {
  EcPoint r(std::in_place_type<Array128>);
  ge25519_double(CastP3(r), CastP3(p));

  return r;
}

void Ed25519Group::DoubleInplace(EcPoint* p) const {
  ge25519_double(CastP3(*p), CastP3(*p));
}

EcPoint Ed25519Group::MulBase(const MPInt& scalar) const {
  sc25519 s;
  if (!MPInt2Scalar(scalar, &s)) {
    return inf_;
  };

  EcPoint r(std::in_place_type<Array128>);
  ge25519_scalarmult_base(CastP3(r), &s);

  return r;
}

EcPoint Ed25519Group::Mul(const EcPoint& point, const MPInt& scalar) const {
  sc25519 s;
  if (!MPInt2Scalar(scalar, &s) || IsInfinity(point)) {
    return inf_;
  };

  EcPoint r(std::in_place_type<Array128>);
  ge25519_scalarmult(CastP3(r), CastP3(point), &s);

  return r;
}

void Ed25519Group::MulInplace(EcPoint* point, const MPInt& scalar) const {
  sc25519 s;
  if (!MPInt2Scalar(scalar, &s) || IsInfinity(*point)) {
    *point = inf_;
  } else {
    ge25519_scalarmult(CastP3(*point), CastP3(*point), &s);
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
  EcPoint r(std::in_place_type<Array128>);
  auto r3 = CastP3(r);

  r3->x = p3->x;
  fe25519_neg(&r3->y, &p3->y);
  fe25519_neg(&r3->z, &p3->z);
  r3->t = p3->t;
  return r;
}

void Ed25519Group::NegateInplace(EcPoint* point) const {
  if (IsInfinity(*point)) {
    return;
  }

  auto* p3 = CastP3(*point);
  fe25519_neg(&p3->y, &p3->y);
  fe25519_neg(&p3->z, &p3->z);
}

AffinePoint Ed25519Group::GetAffinePoint(const EcPoint& point) const {
  const auto* p3 = CastP3(point);
  fe25519 recip;
  fe25519 x;
  fe25519 y;

  fe25519_invert(&recip, &p3->z);
  fe25519_mul(&x, &p3->x, &recip);
  fe25519_mul(&y, &p3->y, &recip);

  return {Fe25519ToMPInt(x), Fe25519ToMPInt(y)};
}

bool Ed25519Group::IsInCurveGroup(const EcPoint& point) const {
  return IsInfinity(point) || ge25519_is_on_curve(CastP3(point)) != 0;
}

bool Ed25519Group::IsInfinity(const EcPoint& point) const {
  static const fe25519 zero = {{0, 0, 0, 0}};
  return fe25519_iseq_vartime(&CastP3(point)->x, &zero) != 0 ||
         fe25519_iseq_vartime(&CastP3(point)->z, &zero) != 0;
}

}  // namespace yacl::crypto::lib25519
