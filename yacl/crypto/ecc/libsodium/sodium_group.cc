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

#include "yacl/crypto/ecc/libsodium/sodium_group.h"

#include <cstring>
#include <functional>
#include <string_view>
#include <utility>
#include <variant>

#include "fmt/format.h"
#include "sodium/private/ed25519_ref10.h"

#include "yacl/base/int128.h"
#include "yacl/math/mpint/mp_int.h"
#include "yacl/utils/spi/type_traits.h"

namespace yacl::crypto::sodium {

void MPIntToFe25519(const MPInt& x, fe25519* out) {
  Array32 buf;
  memset(buf.data(), 0, sizeof(buf));
  x.ToMagBytes(buf.data(), buf.size(), Endian::little);
  fe25519_frombytes(*out, buf.data());
}

SodiumGroup::SodiumGroup(CurveMeta meta, CurveParam param)
    : EcGroupSketch(std::move(meta)), param_(std::move(param)) {
  static_assert(sizeof(ge25519_p3) <= sizeof(Array160));
}

MPInt SodiumGroup::GetCofactor() const { return param_.h; }

MPInt SodiumGroup::GetField() const { return param_.p; }

MPInt SodiumGroup::GetOrder() const { return param_.n; }

std::string SodiumGroup::ToString() const {
  return fmt::format("Curve {} from {}", GetCurveName(), GetLibraryName());
}

EcPoint SodiumGroup::CopyPoint(const EcPoint& point) const {
  if (std::holds_alternative<Array160>(point)) {
    return point;
  }

  if (std::holds_alternative<AffinePoint>(point)) {
    // Convert affine_point to ge25519_p3
    AffinePoint p = std::get<AffinePoint>(point);
    EcPoint r(std::in_place_type<Array160>);
    auto* p3 = CastP3(r);
    // ge25519_p3: (X:Y:Z:T) satisfying x=X/Z, y=Y/Z, XY=ZT
    MPIntToFe25519(p.x, &p3->X);
    MPIntToFe25519(p.y, &p3->Y);
    fe25519_1(p3->Z);
    fe25519_mul(p3->T, p3->X, p3->Y);
    YACL_ENFORCE(IsInCurveGroup(r), "Illegal affine point {}, not in ec group",
                 p);
    return r;
  }

  if (std::holds_alternative<Array32>(point)) {
    // Convert compressed point to ge25519_p3
    // The compressed point format:
    //  - The highest 1 bit: The parity of x-coordinate
    //  - Last 255 bits: The full y-coordinate
    Array32 copy = std::get<Array32>(point);
    auto* p = copy.data();

    // recover x from y
    // https://www.rfc-editor.org/rfc/rfc8032.html#section-6  (recover_x)
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
      return CopyPoint(AffinePoint{0_mp, y});
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
    return CopyPoint(AffinePoint{x, y});
  }

  YACL_THROW("Unsupported EcPoint type {}", point.index());
}

uint64_t SodiumGroup::GetSerializeLength(PointOctetFormat format) const {
  YACL_ENFORCE(format == PointOctetFormat::Autonomous,
               "{} only support Autonomous format, given={}", GetLibraryName(),
               (int)format);
  return 32;
}

Buffer SodiumGroup::SerializePoint(const EcPoint& point,
                                   PointOctetFormat format) const {
  YACL_ENFORCE(format == PointOctetFormat::Autonomous,
               "{} only support Autonomous format, given={}", GetLibraryName(),
               (int)format);

  Buffer buf(32);
  ge25519_p3_tobytes(buf.data<unsigned char>(), CastP3(point));
  return buf;
}

void SodiumGroup::SerializePoint(const EcPoint& point, PointOctetFormat format,
                                 Buffer* buf) const {
  *buf = SerializePoint(point, format);
}

void SodiumGroup::SerializePoint(const EcPoint& point, PointOctetFormat format,
                                 uint8_t* buf, uint64_t buf_size) const {
  YACL_ENFORCE(format == PointOctetFormat::Autonomous,
               "{} only support Autonomous format, given={}", GetLibraryName(),
               (int)format);
  YACL_ENFORCE(buf_size >= 32, "buf size is small than needed 32");
  ge25519_p3_tobytes(buf, CastP3(point));
}

EcPoint SodiumGroup::DeserializePoint(ByteContainerView buf,
                                      PointOctetFormat format) const {
  YACL_ENFORCE(format == PointOctetFormat::Autonomous,
               "{} only support Autonomous format, given={}", GetLibraryName(),
               (int)format);

  EcPoint p(std::in_place_type<Array160>);
  ge25519_frombytes(CastP3(p), buf.data());
  return p;
}

EcPoint SodiumGroup::HashToCurve(HashToCurveStrategy, std::string_view) const {
  YACL_THROW("not impl");
}

size_t SodiumGroup::HashPoint(const EcPoint& point) const {
  const auto* p3 = CastP3(point);
  fe25519 recip;
  fe25519 x;  // x is uint64[5], and every slot only uses 51 bits.

  fe25519_invert(recip, p3->Z);
  fe25519_mul(x, p3->X, recip);

  uint64_t buf[4];  // x is always 255 bits
  fe25519_tobytes(reinterpret_cast<unsigned char*>(buf), x);

  std::hash<uint64_t> h;
  return h(buf[0]) ^ h(buf[1]) ^ h(buf[2]) ^ h(buf[3]);
}

bool SodiumGroup::PointEqual(const EcPoint& p1, const EcPoint& p2) const {
  if (IsInfinity(p1) && IsInfinity(p2)) {
    return true;
  }

  const auto* p1p = CastP3(p1);
  const auto* p2p = CastP3(p2);

  // p1 = (X1/Z1, Y1/Z1) = ((X1*Z2)/(Z1*Z2), (Y1*Z2)/(Z1*Z2));
  // P2 = (X2/Z2, Y2/Z2) = ((Z1*X2)/(Z1*Z2), (Z1*Y2)/(Z1*Z2));
  fe25519 a;
  fe25519 b;
  fe25519_mul(a, p1p->X, p2p->Z);
  fe25519_mul(b, p1p->Z, p2p->X);
  for (size_t i = 0; i < sizeof(fe25519) / sizeof(a[0]); ++i) {
    if (a[i] != b[i]) {
      return false;
    }
  }

  fe25519_mul(a, p1p->Y, p2p->Z);
  fe25519_mul(b, p1p->Z, p2p->Y);
  int128_t buf_a[2];
  int128_t buf_b[2];
  fe25519_tobytes(reinterpret_cast<unsigned char*>(buf_a), a);
  fe25519_tobytes(reinterpret_cast<unsigned char*>(buf_b), b);
  return buf_a[0] == buf_b[0] && buf_a[1] == buf_b[1];
}

const ge25519_p3* SodiumGroup::CastP3(const yacl::crypto::EcPoint& p) {
  YACL_ENFORCE(std::holds_alternative<Array160>(p),
               "Illegal EcPoint, expected Array160, real={}", p.index());
  return reinterpret_cast<const ge25519_p3*>(std::get<Array160>(p).data());
}

ge25519_p3* SodiumGroup::CastP3(EcPoint& p) {
  YACL_ENFORCE(std::holds_alternative<Array160>(p),
               "Illegal EcPoint, expected Array160, real={}", p.index());
  return reinterpret_cast<ge25519_p3*>(std::get<Array160>(p).data());
}

}  // namespace yacl::crypto::sodium
