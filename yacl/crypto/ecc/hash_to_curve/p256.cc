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

#include "yacl/crypto/ecc/hash_to_curve/p256.h"

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
constexpr int kP256KeySize = 32;

// p = 2^256 - 2^224 + 2^192 + 2^96 - 1
constexpr std::array<uint8_t, kP256KeySize> p256_p_bytes = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff};

constexpr std::array<uint8_t, kP256KeySize> p256_a_bytes = {
    0xfc, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff};

constexpr std::array<uint8_t, kP256KeySize> p256_b_bytes = {
    0x4b, 0x60, 0xd2, 0x27, 0x3e, 0x3c, 0xce, 0x3b, 0xf6, 0xb0, 0x53,
    0xcc, 0xb0, 0x06, 0x1d, 0x65, 0xbc, 0x86, 0x98, 0x76, 0x55, 0xbd,
    0xeb, 0xb3, 0xe7, 0x93, 0x3a, 0xaa, 0xd8, 0x35, 0xc6, 0x5a};

constexpr std::array<uint8_t, kP256KeySize> p256_z_bytes = {
    0xf5, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff};

constexpr std::array<uint8_t, kP256KeySize> p256_c1_bytes = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x40, 0x00, 0x00, 0x00, 0xc0, 0xff, 0xff, 0xff, 0x3f};

const yacl::math::MPInt kMpp256 =
    DeserializeMPInt(p256_p_bytes, kP256KeySize, yacl::Endian::little);

const yacl::math::MPInt kMpA =
    DeserializeMPInt(p256_a_bytes, kP256KeySize, yacl::Endian::little);
const yacl::math::MPInt kMpB =
    DeserializeMPInt(p256_b_bytes, kP256KeySize, yacl::Endian::little);
const yacl::math::MPInt kMpZ =
    DeserializeMPInt(p256_z_bytes, kP256KeySize, yacl::Endian::little);

const yacl::math::MPInt kMpC1 =
    DeserializeMPInt(p256_c1_bytes, kP256KeySize, yacl::Endian::little);

// RFC9380 I.1 sqrt for q = 3 (mod 4)
yacl::math::MPInt P256Sqrt(const yacl::math::MPInt &x) {
  // int c1 = 4;
  yacl::math::MPInt z;
  yacl::math::MPInt::PowMod(x, kMpC1, kMpp256, &z);

  return z;
}

std::pair<bool, yacl::math::MPInt> P256SqrtRatio(const yacl::math::MPInt &u,
                                                 const yacl::math::MPInt &v) {
  yacl::math::MPInt r;
  yacl::math::MPInt::InvertMod(v, kMpp256, &r);

  r = r.MulMod(u, kMpp256);

  bool b = IsSquare(r, kMpp256);

  yacl::math::MPInt y;

  if (b) {
    y = P256Sqrt(r);
  } else {
    r = r.MulMod(kMpZ, kMpp256);
    y = P256Sqrt(r);
  }
  return std::make_pair(b, y);
}

std::pair<yacl::math::MPInt, yacl::math::MPInt> MapToCurveSSWUP256(
    yacl::ByteContainerView ubuf) {
  YACL_ENFORCE(ubuf.size() > 0);

  yacl::math::MPInt u;
  u.FromMagBytes(ubuf, yacl::Endian::big);

  yacl::math::MPInt tv1;
  yacl::math::MPInt::MulMod(u, u, kMpp256, &tv1);  // 1. tv1 = u^2

  tv1 = tv1.MulMod(kMpZ, kMpp256);  // 2. tv1 = Z * tv1, where Z = -10

  yacl::math::MPInt tv2;
  yacl::math::MPInt::MulMod(tv1, tv1, kMpp256, &tv2);  // 3. tv2 = tv1 ^ 2

  tv2 = tv2.AddMod(tv1, kMpp256);  // 4. tv2 = tv2 + tv1

  yacl::math::MPInt tv3;
  yacl::math::MPInt::AddMod(tv2, kMp1, kMpp256, &tv3);  // 5. tv3 = tv2 + 1

  tv3 = tv3.MulMod(kMpB, kMpp256);  // 6. tv3 = B * tv3

  yacl::math::MPInt tv4;  // 7. tv4 = CMOV(Z, -tv2, tv2 != 0)
  if (!tv2.IsZero()) {
    yacl::math::MPInt::SubMod(kMpp256, tv2, kMpp256,
                              &tv4);  // intrinsic `Negative` will error
  } else {
    tv4 = kMpZ;
  }

  tv4 = tv4.MulMod(kMpA, kMpp256);  // 8. tv4 = A * tv4

  yacl::math::MPInt::MulMod(tv3, tv3, kMpp256, &tv2);  // 9. tv2 = tv3^2

  yacl::math::MPInt tv6;
  yacl::math::MPInt::MulMod(tv4, tv4, kMpp256, &tv6);  // 10. tv6 = tv4^2

  yacl::math::MPInt tv5;
  yacl::math::MPInt::MulMod(kMpA, tv6, kMpp256, &tv5);  // 11. tv5 = A * tv6

  tv2 = tv2.AddMod(tv5, kMpp256);  // 12. tv2 = tv2 + tv5
  tv2 = tv2.MulMod(tv3, kMpp256);  // 13. tv2 = tv2 * tv3
  tv6 = tv6.MulMod(tv4, kMpp256);  // 14. tv6 = tv6 * tv4

  yacl::math::MPInt::MulMod(kMpB, tv6, kMpp256, &tv5);  // 15. tv5 = B * tv6

  tv2 = tv2.AddMod(tv5, kMpp256);  // 16. tv2 = tv2 + tv5

  yacl::math::MPInt x;
  yacl::math::MPInt::MulMod(tv1, tv3, kMpp256, &x);  // 17. x = tv1 * tv3

  bool is_gx1_square;
  yacl::math::MPInt y1;

  std::tie(is_gx1_square, y1) = P256SqrtRatio(
      tv2, tv6);  // 18. (is_gx1_square, y1) = sqrt_ratio(tv2, tv6)

  yacl::math::MPInt y;
  yacl::math::MPInt::MulMod(tv1, u, kMpp256, &y);  // 19. y = tv1 * u

  y = y.MulMod(y1, kMpp256);  // 20. y = y * y1

  if (is_gx1_square) {
    x = tv3;  // 21. x = CMOV(x, tv3, is_gx1_square)
    y = y1;   // 22. y = CMOV(y, y1, is_gx1_square)
  }

  bool e1 = (Sgn0(u) == Sgn0(y));  // 23. e1 = sgn0(u) == sgn0(y)

  if (!e1) {
    y = kMpp256.SubMod(y, kMpp256);
  }

  yacl::math::MPInt r;
  yacl::math::MPInt::InvertMod(tv4, kMpp256, &r);
  yacl::math::MPInt::MulMod(x, r, kMpp256, &x);  // 25. x = x / tv4

  // crypto::AffinePoint p(x, y);
  // return p;
  return std::make_pair(x, y);
}

// std::vector<uint8_t> CompressP256(const yacl::math::MPInt &x,
//                                   const yacl::math::MPInt &y) {
//   std::vector<uint8_t> p(1 + kEccKeySize);
//   if (y.IsEven()) {
//     p[0] = '\x02';
//   } else {
//     p[0] = '\x03';
//   }
//   yacl::Buffer xbuf = x.ToMagBytes(yacl::Endian::big);
//   std::memcpy(p.data() + 1, xbuf.data(), xbuf.size());
//   return p;
// }

// P256_XMD:SHA-256_SSWU_NU_
// std::vector<uint8_t> EncodeToCurveP256(yacl::ByteContainerView buffer,
crypto::EcPoint EncodeToCurveP256(yacl::ByteContainerView buffer,
                                  const std::string &dst) {
  YACL_ENFORCE((dst.size() >= 16) && (dst.size() <= 255),
               "domain separation tag length: {} not in 16B-255B", dst.size());

  std::vector<std::vector<uint8_t>> u = HashToField(
      buffer, 1, 48, kP256KeySize, crypto::HashAlgorithm::SHA256, kMpp256, dst);
  yacl::math::MPInt qx;
  yacl::math::MPInt qy;

  std::tie(qx, qy) = MapToCurveSSWUP256(u[0]);
  crypto::AffinePoint p(qx, qy);

  // Do not need to clear cofactor when h_eff = 1
  return p;
}

}  // namespace yacl
