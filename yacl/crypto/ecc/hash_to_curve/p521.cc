// Copyright 2025 Guan Yewei
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

#include "yacl/crypto/ecc/hash_to_curve/p521.h"

#include <array>
#include <cstdint>
#include <cstring>
#include <utility>
#include <vector>

#include "yacl/base/buffer.h"
#include "yacl/base/exception.h"
#include "yacl/crypto/ecc/ec_point.h"
#include "yacl/crypto/ecc/hash_to_curve/hash_to_curve_util.h"
#include "yacl/crypto/hash/hash_interface.h"
#include "yacl/crypto/hash/ssl_hash.h"
#include "yacl/math/mpint/mp_int.h"
#include "yacl/utils/spi/type_traits.h"

namespace yacl {
// Curve Parameters
constexpr int kP521KeySize = 66;

// p = 2^521 - 1
constexpr std::array<uint8_t, kP521KeySize> p521_p_bytes = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01};

constexpr std::array<uint8_t, kP521KeySize> p521_a_bytes = {
    0xfc, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01};

constexpr std::array<uint8_t, kP521KeySize> p521_b_bytes = {
    0x00, 0x3f, 0x50, 0x6b, 0xd4, 0x1f, 0x45, 0xef, 0xf1, 0x34, 0x2c,
    0x3d, 0x88, 0xdf, 0x73, 0x35, 0x07, 0xbf, 0xb1, 0x3b, 0xbd, 0xc0,
    0x52, 0x16, 0x7b, 0x93, 0x7e, 0xec, 0x51, 0x39, 0x19, 0x56, 0xe1,
    0x09, 0xf1, 0x8e, 0x91, 0x89, 0xb4, 0xb8, 0xf3, 0x15, 0xb3, 0x99,
    0x5b, 0x72, 0xda, 0xa2, 0xee, 0x40, 0x85, 0xb6, 0xa0, 0x21, 0x9a,
    0x92, 0x1f, 0x9a, 0x1c, 0x8e, 0x61, 0xb9, 0x3e, 0x95, 0x51, 0x00};

constexpr std::array<uint8_t, kP521KeySize> p521_z_bytes = {
    0xfb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01};

constexpr std::array<uint8_t, kP521KeySize> p521_c1_bytes = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00};

const yacl::math::MPInt kMpp521 =
    DeserializeMPInt(p521_p_bytes, kP521KeySize, yacl::Endian::little);

const yacl::math::MPInt kMpA =
    DeserializeMPInt(p521_a_bytes, kP521KeySize, yacl::Endian::little);
const yacl::math::MPInt kMpB =
    DeserializeMPInt(p521_b_bytes, kP521KeySize, yacl::Endian::little);
const yacl::math::MPInt kMpZ =
    DeserializeMPInt(p521_z_bytes, kP521KeySize, yacl::Endian::little);

const yacl::math::MPInt kMpC1 =
    DeserializeMPInt(p521_c1_bytes, kP521KeySize, yacl::Endian::little);

// RFC9380 I.1 sqrt for q = 3 (mod 4)
yacl::math::MPInt P521Sqrt(const yacl::math::MPInt &x) {
  // int c1 = 4;
  yacl::math::MPInt z;
  yacl::math::MPInt::PowMod(x, kMpC1, kMpp521, &z);

  return z;
}

std::pair<bool, yacl::math::MPInt> P521SqrtRatio(const yacl::math::MPInt &u,
                                                 const yacl::math::MPInt &v) {
  yacl::math::MPInt r;
  yacl::math::MPInt::InvertMod(v, kMpp521, &r);

  r = r.MulMod(u, kMpp521);

  bool b = IsSquare(r, kMpp521);

  yacl::math::MPInt y;

  if (b) {
    y = P521Sqrt(r);
  } else {
    r = r.MulMod(kMpZ, kMpp521);
    y = P521Sqrt(r);
  }
  return std::make_pair(b, y);
}

std::pair<yacl::math::MPInt, yacl::math::MPInt> MapToCurveSSWUP521(
    yacl::ByteContainerView ubuf) {
  YACL_ENFORCE(ubuf.size() > 0);

  yacl::math::MPInt u;
  u.FromMagBytes(ubuf, yacl::Endian::big);

  yacl::math::MPInt tv1;
  yacl::math::MPInt::MulMod(u, u, kMpp521, &tv1);  // 1. tv1 = u^2

  tv1 = tv1.MulMod(kMpZ, kMpp521);  // 2. tv1 = Z * tv1, where Z = -10

  yacl::math::MPInt tv2;
  yacl::math::MPInt::MulMod(tv1, tv1, kMpp521, &tv2);  // 3. tv2 = tv1 ^ 2

  tv2 = tv2.AddMod(tv1, kMpp521);  // 4. tv2 = tv2 + tv1

  yacl::math::MPInt tv3;
  yacl::math::MPInt::AddMod(tv2, kMp1, kMpp521, &tv3);  // 5. tv3 = tv2 + 1

  tv3 = tv3.MulMod(kMpB, kMpp521);  // 6. tv3 = B * tv3

  yacl::math::MPInt tv4;  // 7. tv4 = CMOV(Z, -tv2, tv2 != 0)
  if (!tv2.IsZero()) {
    yacl::math::MPInt::SubMod(kMpp521, tv2, kMpp521,
                              &tv4);  // intrinsic `Negative` will error
  } else {
    tv4 = kMpZ;
  }

  tv4 = tv4.MulMod(kMpA, kMpp521);  // 8. tv4 = A * tv4

  yacl::math::MPInt::MulMod(tv3, tv3, kMpp521, &tv2);  // 9. tv2 = tv3^2

  yacl::math::MPInt tv6;
  yacl::math::MPInt::MulMod(tv4, tv4, kMpp521, &tv6);  // 10. tv6 = tv4^2

  yacl::math::MPInt tv5;
  yacl::math::MPInt::MulMod(kMpA, tv6, kMpp521, &tv5);  // 11. tv5 = A * tv6

  tv2 = tv2.AddMod(tv5, kMpp521);  // 12. tv2 = tv2 + tv5
  tv2 = tv2.MulMod(tv3, kMpp521);  // 13. tv2 = tv2 * tv3
  tv6 = tv6.MulMod(tv4, kMpp521);  // 14. tv6 = tv6 * tv4

  yacl::math::MPInt::MulMod(kMpB, tv6, kMpp521, &tv5);  // 15. tv5 = B * tv6

  tv2 = tv2.AddMod(tv5, kMpp521);  // 16. tv2 = tv2 + tv5

  yacl::math::MPInt x;
  yacl::math::MPInt::MulMod(tv1, tv3, kMpp521, &x);  // 17. x = tv1 * tv3

  bool is_gx1_square;
  yacl::math::MPInt y1;

  std::tie(is_gx1_square, y1) = P521SqrtRatio(
      tv2, tv6);  // 18. (is_gx1_square, y1) = sqrt_ratio(tv2, tv6)

  yacl::math::MPInt y;
  yacl::math::MPInt::MulMod(tv1, u, kMpp521, &y);  // 19. y = tv1 * u

  y = y.MulMod(y1, kMpp521);  // 20. y = y * y1

  if (is_gx1_square) {
    x = tv3;  // 21. x = CMOV(x, tv3, is_gx1_square)
    y = y1;   // 22. y = CMOV(y, y1, is_gx1_square)
  }

  bool e1 = (Sgn0(u) == Sgn0(y));  // 23. e1 = sgn0(u) == sgn0(y)

  if (!e1) {
    y = kMpp521.SubMod(y, kMpp521);
  }

  yacl::math::MPInt r;
  yacl::math::MPInt::InvertMod(tv4, kMpp521, &r);
  yacl::math::MPInt::MulMod(x, r, kMpp521, &x);  // 25. x = x / tv4

  return std::make_pair(x, y);
}

// P521_XMD:SHA-512_SSWU_NU_
crypto::EcPoint EncodeToCurveP521(yacl::ByteContainerView buffer,
                                  const std::string &dst) {
  YACL_ENFORCE((dst.size() >= 16) && (dst.size() <= 255),
               "domain separation tag length: {} not in 16B-255B", dst.size());

  std::vector<std::vector<uint8_t>> u = HashToField(
      buffer, 1, 98, kP521KeySize, crypto::HashAlgorithm::SHA512, kMpp521, dst);
  yacl::math::MPInt qx;
  yacl::math::MPInt qy;

  std::tie(qx, qy) = MapToCurveSSWUP521(u[0]);
  // crypto::EcPoint p = MapToCurveSSWU(u[0]);
  crypto::AffinePoint p(qx, qy);

  // Do not need to clear cofactor when h_eff = 1
  return p;
}

}  // namespace yacl
