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

#include "yacl/crypto/ecc/lib25519/lib25519_group.h"

namespace yacl::crypto::lib25519 {

void MPIntToFe25519(const MPInt& x, fe25519* out) {
  Array32 buf;
  memset(buf.data(), 0, sizeof(buf));
  x.ToMagBytes(buf.data(), buf.size(), Endian::little);
  fe25519_unpack(out, buf.data());
}

Lib25519Group::Lib25519Group(CurveMeta meta, CurveParam param)
    : EcGroupSketch(std::move(meta)), param_(std::move(param)) {
  static_assert(sizeof(ge25519_p3) <= sizeof(Array128));
}

MPInt Lib25519Group::GetCofactor() const { return param_.h; }

MPInt Lib25519Group::GetField() const { return param_.p; }

MPInt Lib25519Group::GetOrder() const { return param_.n; }

std::string Lib25519Group::ToString() const {
  return fmt::format("Curve {} from {}", GetCurveName(), GetLibraryName());
}

EcPoint Lib25519Group::CopyPoint(const EcPoint& point) const {
  if (std::holds_alternative<Array128>(point)) {
    return point;
  }

  if (std::holds_alternative<AffinePoint>(point)) {
    // Convert affine_point to ge25519_p3
    AffinePoint p = std::get<AffinePoint>(point);
    EcPoint r(std::in_place_type<Array128>);
    auto* p3 = CastP3(r);
    // ge25519_p3: (X:Y:Z:T) satisfying x=X/Z, y=Y/Z, XY=ZT
    MPIntToFe25519(p.x, &p3->x);
    MPIntToFe25519(p.y, &p3->y);
    fe25519_setint(&p3->z, 1);
    fe25519_mul(&p3->t, &p3->x, &p3->y);
    YACL_ENFORCE(IsInCurveGroup(r), "Illegal affine point {}, not in ec group",
                 p);
    return r;
  }

  // TODO: if (std::holds_alternative<Array32>(point)) ...

  YACL_THROW("Unsupported EcPoint type {}", point.index());
}

uint64_t Lib25519Group::GetSerializeLength(PointOctetFormat format) const {
  YACL_ENFORCE(format == PointOctetFormat::Autonomous,
               "{} only support Autonomous format, given={}", GetLibraryName(),
               (int)format);
  return 32;
}

Buffer Lib25519Group::SerializePoint(const EcPoint& point,
                                     PointOctetFormat format) const {
  YACL_ENFORCE(format == PointOctetFormat::Autonomous,
               "{} only support Autonomous format, given={}", GetLibraryName(),
               (int)format);

  Buffer buf(32);
  ge25519_pack(buf.data<unsigned char>(), CastP3(point));
  return buf;
}

void Lib25519Group::SerializePoint(const EcPoint& point,
                                   PointOctetFormat format, Buffer* buf) const {
  *buf = SerializePoint(point, format);
}

void Lib25519Group::SerializePoint(const EcPoint& point,
                                   PointOctetFormat format, uint8_t* buf,
                                   uint64_t buf_size) const {
  YACL_ENFORCE(format == PointOctetFormat::Autonomous,
               "{} only support Autonomous format, given={}", GetLibraryName(),
               (int)format);
  YACL_ENFORCE(buf_size >= 32, "buf size is small than needed 32");
  ge25519_pack(buf, CastP3(point));
}

EcPoint Lib25519Group::DeserializePoint(ByteContainerView buf,
                                        PointOctetFormat format) const {
  YACL_ENFORCE(format == PointOctetFormat::Autonomous,
               "{} only support Autonomous format, given={}", GetLibraryName(),
               (int)format);

  EcPoint p(std::in_place_type<Array128>);
  YACL_ENFORCE(ge25519_unpack_vartime(CastP3(p), buf.data()) == 1,
               "deserialize point failed");

  return p;
}

EcPoint Lib25519Group::HashToCurve(HashToCurveStrategy,
                                   std::string_view) const {
  YACL_THROW("not implemented");
}

size_t Lib25519Group::HashPoint(const EcPoint& point) const {
  const auto* p3 = CastP3(point);
  fe25519 recip;
  fe25519 x;

  fe25519_invert(&recip, &p3->z);
  fe25519_mul(&x, &p3->x, &recip);

  uint64_t buf[4];  // x is always 255 bits
  fe25519_pack(reinterpret_cast<unsigned char*>(buf), &x);

  std::hash<uint64_t> h;
  return h(buf[0]) ^ h(buf[1]) ^ h(buf[2]) ^ h(buf[3]);
}

bool Lib25519Group::PointEqual(const EcPoint& p1, const EcPoint& p2) const {
  if (IsInfinity(p1) && IsInfinity(p2)) {
    return true;
  }

  const auto* p1p = CastP3(p1);
  const auto* p2p = CastP3(p2);

  // p1 = (X1/Z1, Y1/Z1) = ((X1*Z2)/(Z1*Z2), (Y1*Z2)/(Z1*Z2));
  // P2 = (X2/Z2, Y2/Z2) = ((Z1*X2)/(Z1*Z2), (Z1*Y2)/(Z1*Z2));
  fe25519 a;
  fe25519 b;
  fe25519_mul(&a, &p1p->x, &p2p->z);
  fe25519_mul(&b, &p1p->z, &p2p->x);
  for (size_t i = 0; i < sizeof(fe25519) / sizeof(a.v[0]); ++i) {
    if (a.v[i] != b.v[i]) {
      return false;
    }
  }

  fe25519_mul(&a, &p1p->y, &p2p->z);
  fe25519_mul(&b, &p1p->z, &p2p->y);
  uint128_t buf_a[2];
  uint128_t buf_b[2];
  fe25519_pack(reinterpret_cast<unsigned char*>(buf_a), &a);
  fe25519_pack(reinterpret_cast<unsigned char*>(buf_b), &b);
  return buf_a[0] == buf_b[0] && buf_a[1] == buf_b[1];
}

const ge25519_p3* Lib25519Group::CastP3(const yacl::crypto::EcPoint& p) {
  YACL_ENFORCE(std::holds_alternative<Array128>(p),
               "Illegal EcPoint, expected Array128, real={}", p.index());
  return reinterpret_cast<const ge25519_p3*>(std::get<Array128>(p).data());
}

ge25519_p3* Lib25519Group::CastP3(EcPoint& p) {
  YACL_ENFORCE(std::holds_alternative<Array128>(p),
               "Illegal EcPoint, expected Array128, real={}", p.index());
  return reinterpret_cast<ge25519_p3*>(std::get<Array128>(p).data());
}

}  // namespace yacl::crypto::lib25519
