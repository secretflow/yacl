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

#include "yacl/crypto/ecc/hash_to_curve/p384.h"

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
constexpr int kP384KeySize = 48;

// p = 2^384 - 2^128 - 2^96 + 2^32 - 1
constexpr std::array<uint8_t, kP384KeySize> p384_p_bytes = {
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

constexpr std::array<uint8_t, kP384KeySize> p384_a_bytes = {
    0xfc, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

constexpr std::array<uint8_t, kP384KeySize> p384_b_bytes = {
    0xef, 0x2a, 0xec, 0xd3, 0xed, 0xc8, 0x85, 0x2a, 0x9d, 0xd1, 0x2e, 0x8a,
    0x8d, 0x39, 0x56, 0xc6, 0x5a, 0x87, 0x13, 0x50, 0x8f, 0x08, 0x14, 0x03,
    0x12, 0x41, 0x81, 0xfe, 0x6e, 0x9c, 0x1d, 0x18, 0x19, 0x2d, 0xf8, 0xe3,
    0x6b, 0x05, 0x8e, 0x98, 0xe4, 0xe7, 0x3e, 0xe2, 0xa7, 0x2f, 0x31, 0xb3};

constexpr std::array<uint8_t, kP384KeySize> p384_z_bytes = {
    0xf3, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

constexpr std::array<uint8_t, 48> p384_c1_bytes = {
    0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0,
    0xff, 0xff, 0xff, 0xbf, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f};

const yacl::math::MPInt kMpp384 =
    DeserializeMPInt(p384_p_bytes, kP384KeySize, yacl::Endian::little);

const yacl::math::MPInt kMpA =
    DeserializeMPInt(p384_a_bytes, kP384KeySize, yacl::Endian::little);
const yacl::math::MPInt kMpB =
    DeserializeMPInt(p384_b_bytes, kP384KeySize, yacl::Endian::little);
const yacl::math::MPInt kMpZ =
    DeserializeMPInt(p384_z_bytes, kP384KeySize, yacl::Endian::little);

const yacl::math::MPInt kMpC1 =
    DeserializeMPInt(p384_c1_bytes, kP384KeySize, yacl::Endian::little);

// RFC9380 I.1 sqrt for q = 3 (mod 4)
yacl::math::MPInt P384Sqrt(const yacl::math::MPInt &x) {
  // int c1 = 4;
  yacl::math::MPInt z;
  yacl::math::MPInt::PowMod(x, kMpC1, kMpp384, &z);

  return z;
}

std::pair<bool, yacl::math::MPInt> P384SqrtRatio(const yacl::math::MPInt &u,
                                                 const yacl::math::MPInt &v) {
  yacl::math::MPInt r;
  yacl::math::MPInt::InvertMod(v, kMpp384, &r);

  r = r.MulMod(u, kMpp384);

  bool b = IsSquare(r, kMpp384);

  yacl::math::MPInt y;

  if (b) {
    y = P384Sqrt(r);
  } else {
    r = r.MulMod(kMpZ, kMpp384);
    y = P384Sqrt(r);
  }
  return std::make_pair(b, y);
}

std::pair<yacl::math::MPInt, yacl::math::MPInt> MapToCurveSSWUP384(
    yacl::ByteContainerView ubuf) {
  YACL_ENFORCE(ubuf.size() > 0);

  yacl::math::MPInt u;
  u.FromMagBytes(ubuf, yacl::Endian::big);

  yacl::math::MPInt tv1;
  yacl::math::MPInt::MulMod(u, u, kMpp384, &tv1);  // 1. tv1 = u^2

  tv1 = tv1.MulMod(kMpZ, kMpp384);  // 2. tv1 = Z * tv1, where Z = -10

  yacl::math::MPInt tv2;
  yacl::math::MPInt::MulMod(tv1, tv1, kMpp384, &tv2);  // 3. tv2 = tv1 ^ 2

  tv2 = tv2.AddMod(tv1, kMpp384);  // 4. tv2 = tv2 + tv1

  yacl::math::MPInt tv3;
  yacl::math::MPInt::AddMod(tv2, kMp1, kMpp384, &tv3);  // 5. tv3 = tv2 + 1

  tv3 = tv3.MulMod(kMpB, kMpp384);  // 6. tv3 = B * tv3

  yacl::math::MPInt tv4;  // 7. tv4 = CMOV(Z, -tv2, tv2 != 0)
  if (!tv2.IsZero()) {
    yacl::math::MPInt::SubMod(kMpp384, tv2, kMpp384,
                              &tv4);  // intrinsic `Negative` will error
  } else {
    tv4 = kMpZ;
  }

  tv4 = tv4.MulMod(kMpA, kMpp384);  // 8. tv4 = A * tv4

  yacl::math::MPInt::MulMod(tv3, tv3, kMpp384, &tv2);  // 9. tv2 = tv3^2

  yacl::math::MPInt tv6;
  yacl::math::MPInt::MulMod(tv4, tv4, kMpp384, &tv6);  // 10. tv6 = tv4^2

  yacl::math::MPInt tv5;
  yacl::math::MPInt::MulMod(kMpA, tv6, kMpp384, &tv5);  // 11. tv5 = A * tv6

  tv2 = tv2.AddMod(tv5, kMpp384);  // 12. tv2 = tv2 + tv5
  tv2 = tv2.MulMod(tv3, kMpp384);  // 13. tv2 = tv2 * tv3
  tv6 = tv6.MulMod(tv4, kMpp384);  // 14. tv6 = tv6 * tv4

  yacl::math::MPInt::MulMod(kMpB, tv6, kMpp384, &tv5);  // 15. tv5 = B * tv6

  tv2 = tv2.AddMod(tv5, kMpp384);  // 16. tv2 = tv2 + tv5

  yacl::math::MPInt x;
  yacl::math::MPInt::MulMod(tv1, tv3, kMpp384, &x);  // 17. x = tv1 * tv3

  bool is_gx1_square;
  yacl::math::MPInt y1;

  std::tie(is_gx1_square, y1) = P384SqrtRatio(
      tv2, tv6);  // 18. (is_gx1_square, y1) = sqrt_ratio(tv2, tv6)

  yacl::math::MPInt y;
  yacl::math::MPInt::MulMod(tv1, u, kMpp384, &y);  // 19. y = tv1 * u

  y = y.MulMod(y1, kMpp384);  // 20. y = y * y1

  if (is_gx1_square) {
    x = tv3;  // 21. x = CMOV(x, tv3, is_gx1_square)
    y = y1;   // 22. y = CMOV(y, y1, is_gx1_square)
  }

  bool e1 = (Sgn0(u) == Sgn0(y));  // 23. e1 = sgn0(u) == sgn0(y)

  if (!e1) {
    y = kMpp384.SubMod(y, kMpp384);
  }

  yacl::math::MPInt r;
  yacl::math::MPInt::InvertMod(tv4, kMpp384, &r);
  yacl::math::MPInt::MulMod(x, r, kMpp384, &x);  // 25. x = x / tv4

  // crypto::AffinePoint p(x, y);
  // return p;
  return std::make_pair(x, y);
}

// P384_XMD:SHA-384_SSWU_NU_
crypto::EcPoint EncodeToCurveP384(yacl::ByteContainerView buffer,
                                  const std::string &dst) {
  YACL_ENFORCE((dst.size() >= 16) && (dst.size() <= 255),
               "domain separation tag length: {} not in 16B-255B", dst.size());

  std::vector<std::vector<uint8_t>> u = HashToField(
      buffer, 1, 72, kP384KeySize, crypto::HashAlgorithm::SHA384, kMpp384, dst);
  yacl::math::MPInt qx;
  yacl::math::MPInt qy;

  std::tie(qx, qy) = MapToCurveSSWUP384(u[0]);
  // crypto::EcPoint p = MapToCurveSSWU(u[0]);
  crypto::AffinePoint p(qx, qy);

  // Do not need to clear cofactor when h_eff = 1
  // std::vector<uint8_t> p = CompressP256(qx, qy);
  return p;
}

}  // namespace yacl
