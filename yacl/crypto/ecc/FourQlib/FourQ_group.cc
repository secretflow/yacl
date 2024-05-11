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

#include "yacl/crypto/ecc/FourQlib/FourQ_group.h"

namespace yacl::crypto::FourQ {

// Elements (a+b*i) over GF(p^2), where a and b are defined over GF(p), are
// encoded as a||b, with a in the least significant position.
MPInt F2elm2MPInt(const f2elm_t f2elm) {
  MPInt r(0, 256);
  r.FromMagBytes(yacl::ByteContainerView(f2elm, 32), Endian::little);
  return r;
}

// Reverse operation of F2elm2MPInt
void MPIntToF2elm(const MPInt& x, f2elm_t f2elm) {
  memset(f2elm, 0, 32);
  x.ToMagBytes(reinterpret_cast<unsigned char*>(f2elm), 32, Endian::little);
}

FourQGroup::FourQGroup(const CurveMeta& meta) : EcGroupSketch(meta) {
  n_ =
      MPInt("0x29CBC14E5E0A72F05397829CBC14E5DFBD004DFE0F79992FB2540EC7768CE7");
  h_ = MPInt("0x188");

  g_ = MulBase(1_mp);
}

void FourQGroup::MPIntToDigits(const MPInt& scalar, digit_t* out,
                               unsigned int nwords) const {
  auto s = scalar.Mod(n_);
  unsigned int size = sizeof(digit_t) * nwords;
  memset(out, 0, size);
  s.ToMagBytes(reinterpret_cast<unsigned char*>(out), size, Endian::little);
}

MPInt FourQGroup::GetCofactor() const { return h_; }

MPInt FourQGroup::GetField() const { YACL_THROW("not impl"); }

MPInt FourQGroup::GetOrder() const { return n_; }

EcPoint FourQGroup::GetGenerator() const { return g_; }

std::string FourQGroup::ToString() const {
  return fmt::format("Curve {} from {}", GetCurveName(), GetLibraryName());
}

EcPoint FourQGroup::Add(const EcPoint& p1, const EcPoint& p2) const {
  point_extproj_precomp_t p1_r2;
  R1_to_R2(const_cast<point_extproj*>(CastR1(p1)), p1_r2);

  point_extproj_precomp_t p2_r3;
  R1_to_R3(const_cast<point_extproj*>(CastR1(p2)), p2_r3);

  EcPoint r(std::in_place_type<Array160>);
  eccadd_core(p1_r2, p2_r3, CastR1(r));

  return r;
}

void FourQGroup::AddInplace(EcPoint* p1, const EcPoint& p2) const {
  point_extproj_precomp_t p2_r3;
  R1_to_R2(const_cast<point_extproj*>(CastR1(p2)), p2_r3);

  eccadd(p2_r3, CastR1(*p1));
}

EcPoint FourQGroup::Double(const EcPoint& p) const {
  auto r = p;
  eccdouble(CastR1(r));

  return r;
}

void FourQGroup::DoubleInplace(EcPoint* p) const { eccdouble(CastR1(*p)); }

EcPoint FourQGroup::Mul(const EcPoint& point, const MPInt& scalar) const {
  digit_t digits[NWORDS_ORDER];
  MPIntToDigits(scalar, digits, NWORDS_ORDER);
  point_t p;
  point_t q;
  auto point_cpy = point;
  eccnorm(CastR1(point_cpy), p);
  ecc_mul(p, digits, q, false);

  EcPoint r(std::in_place_type<Array160>);
  point_setup(q, CastR1(r));

  return r;
}

void FourQGroup::MulInplace(EcPoint* point, const MPInt& scalar) const {
  digit_t digits[NWORDS_ORDER];
  MPIntToDigits(scalar, digits, NWORDS_ORDER);
  point_t p;
  eccnorm(CastR1(*point), p);
  ecc_mul(p, digits, p, false);

  point_setup(p, CastR1(*point));
}

EcPoint FourQGroup::MulBase(const MPInt& scalar) const {
  digit_t digits[NWORDS_ORDER];
  MPIntToDigits(scalar, digits, NWORDS_ORDER);

  point_t q;
  ecc_mul_fixed(digits, q);

  EcPoint r(std::in_place_type<Array160>);
  point_setup(q, CastR1(r));

  return r;
}

EcPoint FourQGroup::MulDoubleBase(const MPInt& s1, const MPInt& s2,
                                  const EcPoint& p2) const {
  digit_t s1_digits[NWORDS_ORDER], s2_digits[NWORDS_ORDER];
  MPIntToDigits(s1, s1_digits, NWORDS_ORDER);
  MPIntToDigits(s2, s2_digits, NWORDS_ORDER);

  point_t p;
  point_t q;
  auto p2_cpy = p2;
  eccnorm(CastR1(p2_cpy), p);

  ecc_mul_double(s1_digits, p, s2_digits, q);

  EcPoint r(std::in_place_type<Array160>);
  point_setup(q, CastR1(r));

  return r;
}

EcPoint FourQGroup::Negate(const EcPoint& point) const {
  if (IsInfinity(point)) {
    return point;
  }

  auto r = point;
  auto* p = CastR1(r);

  fp2neg1271(p->y);
  fp2neg1271(p->z);

  return r;
}

void FourQGroup::NegateInplace(EcPoint* point) const {
  if (IsInfinity(*point)) {
    return;
  }

  auto* p = CastR1(*point);
  fp2neg1271(p->y);
  fp2neg1271(p->z);
}

EcPoint FourQGroup::CopyPoint(const EcPoint& point) const {
  if (std::holds_alternative<Array160>(point)) {
    return point;
  }

  if (std::holds_alternative<AffinePoint>(point)) {
    AffinePoint p = std::get<AffinePoint>(point);

    point_t q;
    MPIntToF2elm(p.x, q->x);
    MPIntToF2elm(p.y, q->y);

    EcPoint r(std::in_place_type<Array160>);
    point_setup(q, CastR1(r));

    YACL_ENFORCE(IsInCurveGroup(r), "Illegal affine point {}, not in ec group",
                 p);

    return r;
  }

  YACL_THROW("Unsupported EcPoint type {}", point.index());
}

AffinePoint FourQGroup::GetAffinePoint(const EcPoint& point) const {
  point_t p;
  auto point_cpy = point;
  eccnorm(CastR1(point_cpy), p);

  return {F2elm2MPInt(p->x), F2elm2MPInt(p->y)};
}

uint64_t FourQGroup::GetSerializeLength(PointOctetFormat format) const {
  YACL_ENFORCE(format == PointOctetFormat::Autonomous,
               "{} only support Autonomous format, given={}", GetLibraryName(),
               (int)format);
  return 32;
}

Buffer FourQGroup::SerializePoint(const EcPoint& point,
                                  PointOctetFormat format) const {
  YACL_ENFORCE(format == PointOctetFormat::Autonomous,
               "{} only support Autonomous format, given={}", GetLibraryName(),
               (int)format);

  auto point_cpy = point;
  point_t p;
  eccnorm(CastR1(point_cpy), p);

  Buffer buf(32);
  encode(p, buf.data<unsigned char>());

  return buf;
}

void FourQGroup::SerializePoint(const EcPoint& point, PointOctetFormat format,
                                Buffer* buf) const {
  *buf = SerializePoint(point, format);
}

void FourQGroup::SerializePoint(const EcPoint& point, PointOctetFormat format,
                                uint8_t* buf, uint64_t buf_size) const {
  YACL_ENFORCE(format == PointOctetFormat::Autonomous,
               "{} only support Autonomous format, given={}", GetLibraryName(),
               (int)format);
  YACL_ENFORCE(buf_size >= 32, "buf size is small than needed 32");

  auto point_cpy = point;
  point_t p;
  eccnorm(CastR1(point_cpy), p);
  encode(p, buf);
}

EcPoint FourQGroup::DeserializePoint(ByteContainerView buf,
                                     PointOctetFormat format) const {
  YACL_ENFORCE(format == PointOctetFormat::Autonomous,
               "{} only support Autonomous format, given={}", GetLibraryName(),
               (int)format);

  point_t p;
  auto status = decode(buf.data(), p);
  YACL_ENFORCE(status == ECCRYPTO_SUCCESS, FourQ_get_error_message(status));

  EcPoint r(std::in_place_type<Array160>);
  point_setup(p, CastR1(r));

  return r;
}

EcPoint FourQGroup::HashToCurve(HashToCurveStrategy, std::string_view) const {
  YACL_THROW("not impl");
}

size_t FourQGroup::HashPoint(const EcPoint& point) const {
  auto* p = const_cast<point_extproj*>(CastR1(point));
  f2elm_t x;
  f2elm_t z;

  fp2copy1271(p->z, z);
  fp2inv1271(z);
  fp2mul1271(p->x, z, x);
  mod1271(x[0]);
  mod1271(x[1]);

  digit_t* buf = reinterpret_cast<digit_t*>(x);

  // Assume digit_t size of 64 bits
  std::hash<uint64_t> h;
  // h(buf[0]) ^ ... ^ h(buf[3]) produce the same hash value for P and -P, while
  // h(buf[0]) ^ ... ^ h(buf[2]) does not
  return h(buf[0]) ^ h(buf[1]) ^ h(buf[2]);  // ^ h(buf[3])
}

bool FourQGroup::PointEqual(const EcPoint& p1, const EcPoint& p2) const {
  if (IsInfinity(p1) && IsInfinity(p2)) {
    return true;
  }

  auto* p1p = const_cast<point_extproj*>(CastR1(p1));
  auto* p2p = const_cast<point_extproj*>(CastR1(p2));

  // p1 = (X1/Z1, Y1/Z1) = ((X1*Z2)/(Z1*Z2), (Y1*Z2)/(Z1*Z2));
  // P2 = (X2/Z2, Y2/Z2) = ((Z1*X2)/(Z1*Z2), (Z1*Y2)/(Z1*Z2));
  f2elm_t a;
  f2elm_t b;
  fp2mul1271(p1p->x, p2p->z, a);
  fp2mul1271(p1p->z, p2p->x, b);
  auto* pa = reinterpret_cast<digit_t*>(a);
  auto* pb = reinterpret_cast<digit_t*>(b);
  for (size_t i = 0; i < 2 * NWORDS_FIELD; ++i) {
    if (pa[i] != pb[i]) {
      return false;
    }
  }

  fp2mul1271(p1p->y, p2p->z, a);
  fp2mul1271(p1p->z, p2p->y, b);
  pa = reinterpret_cast<digit_t*>(a);
  pb = reinterpret_cast<digit_t*>(b);
  for (size_t i = 0; i < 2 * NWORDS_FIELD; ++i) {
    if (pa[i] != pb[i]) {
      return false;
    }
  }

  return true;
}

bool FourQGroup::IsInCurveGroup(const EcPoint& point) const {
  // point must be in affine coordinates (that is: z == 1)
  auto p = point;
  point_t q;
  eccnorm(CastR1(p), q);
  point_setup(q, CastR1(p));  // make z = 1

  return ecc_point_validate(CastR1(p));
}

bool FourQGroup::IsInfinity(const EcPoint& point) const {
  auto* x =
      const_cast<digit_t*>(reinterpret_cast<const digit_t*>(CastR1(point)->x));
  auto* z =
      const_cast<digit_t*>(reinterpret_cast<const digit_t*>(CastR1(point)->z));

  return is_zero_ct(x, 2 * NWORDS_FIELD) || is_zero_ct(z, 2 * NWORDS_FIELD);
}

const point_extproj* FourQGroup::CastR1(const EcPoint& p) {
  YACL_ENFORCE(std::holds_alternative<Array160>(p),
               "Illegal EcPoint, expected Array160, real={}", p.index());
  return reinterpret_cast<const point_extproj*>(std::get<Array160>(p).data());
}

point_extproj* FourQGroup::CastR1(EcPoint& p) {
  YACL_ENFORCE(std::holds_alternative<Array160>(p),
               "Illegal EcPoint, expected Array160, real={}", p.index());
  return reinterpret_cast<point_extproj*>(std::get<Array160>(p).data());
}

}  // namespace yacl::crypto::FourQ