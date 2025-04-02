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

#include "yacl/crypto/ecc/hash_to_curve/curve25519.h"

#include <cmath>
#include <string>
#include <utility>
#include <vector>

#include "absl/strings/escaping.h"

#include "yacl/crypto/ecc/ec_point.h"
#include "yacl/crypto/ecc/hash_to_curve/hash_to_curve_util.h"
#include "yacl/crypto/hash/hash_interface.h"
#include "yacl/crypto/hash/ssl_hash.h"
#include "yacl/math/mpint/mp_int.h"
#include "yacl/utils/spi/type_traits.h"

namespace yacl {

constexpr int kCurve25519KeySize = 32;

// y^2 = x^3 + 486662 * x^2 + x
// p = 2^255 - 19
constexpr std::array<uint8_t, kCurve25519KeySize> p_bytes = {
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f};

// c1 = (p+3)/8
constexpr std::array<uint8_t, kCurve25519KeySize> c1_bytes = {
    0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf};

// c2 = 2^c1
constexpr std::array<uint8_t, kCurve25519KeySize> c2_bytes = {
    0xb1, 0xa0, 0xe,  0x4a, 0x27, 0x1b, 0xee, 0xc4, 0x78, 0xe4, 0x2f,
    0xad, 0x6,  0x18, 0x43, 0x2f, 0xa7, 0xd7, 0xfb, 0x3d, 0x99, 0x0,
    0x4d, 0x2b, 0xb,  0xdf, 0xc1, 0x4f, 0x80, 0x24, 0x83, 0x2b};

// c3 = sqrt(p-1)
constexpr std::array<uint8_t, kCurve25519KeySize> sqrtm1_bytes = {
    0x3d, 0x5f, 0xf1, 0xb5, 0xd8, 0xe4, 0x11, 0x3b, 0x87, 0x1b, 0xd0,
    0x52, 0xf9, 0xe7, 0xbc, 0xd0, 0x58, 0x28, 0x4,  0xc2, 0x66, 0xff,
    0xb2, 0xd4, 0xf4, 0x20, 0x3e, 0xb0, 0x7f, 0xdb, 0x7c, 0x54};

// c4 = (p-5)/8
constexpr std::array<uint8_t, kCurve25519KeySize> c4_bytes = {
    0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf};

constexpr size_t k25519J = 486662;
const yacl::math::MPInt kMp3(3);
const yacl::math::MPInt kMp8(8);
const yacl::math::MPInt kMp25519J(k25519J);
const yacl::math::MPInt kMp25519 =
    DeserializeMPInt(p_bytes, kCurve25519KeySize, yacl::Endian::little);
const yacl::math::MPInt kMpSqrtm1 =
    DeserializeMPInt(sqrtm1_bytes, kCurve25519KeySize, yacl::Endian::little);

const yacl::math::MPInt kMpC1 =
    DeserializeMPInt(c1_bytes, kCurve25519KeySize, yacl::Endian::little);
const yacl::math::MPInt kMpC2 =
    DeserializeMPInt(c2_bytes, kCurve25519KeySize, yacl::Endian::little);
const yacl::math::MPInt kMpC4 =
    DeserializeMPInt(c4_bytes, kCurve25519KeySize, yacl::Endian::little);

// RFC9380 I.2 sqrt for q = 5 (mod 8)
yacl::math::MPInt Curve25519Sqrt(const yacl::math::MPInt &v,
                                 const yacl::math::MPInt &mod) {
  yacl::math::MPInt c2;
  yacl::math::MPInt::Add(mod, kMp3, &c2);
  yacl::math::MPInt c;
  yacl::math::MPInt d;
  yacl::math::MPInt::Div(c2, kMp8, &c, &d);
  c2 = c;

  yacl::math::MPInt tv1 = v.PowMod(c2, mod);
  yacl::math::MPInt tv2 = tv1.MulMod(kMpSqrtm1, mod);

  c = tv1.MulMod(tv1, mod);
  if (c == v) {
    return tv1;
  }
  return tv2;
}

// RFC9380 G.2.  Elligator 2 Method  map_to_curve_elligator2
[[maybe_unused]] std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
MapToCurveG2(yacl::ByteContainerView ubuf) {
  YACL_ENFORCE(ubuf.size() > 0);

  yacl::math::MPInt u;
  u.FromMagBytes(ubuf, yacl::Endian::big);

  yacl::math::MPInt tv1;
  yacl::math::MPInt::MulMod(u, u, kMp25519, &tv1);  // 1. tv1 = u^2

  tv1 = tv1.MulMod(kMp2, kMp25519);  // 2. tv1 = 2*tv1

  yacl::math::MPInt xd;
  yacl::math::MPInt::AddMod(tv1, kMp1, kMp25519, &xd);  // 3. xd = tv1 + 1

  yacl::math::MPInt x1n = kMp25519J;
  x1n.NegateInplace();  // 4. x1n = -J

  yacl::math::MPInt tv2;
  yacl::math::MPInt::MulMod(xd, xd, kMp25519, &tv2);  // 5. tv2 = xd^2

  yacl::math::MPInt gxd;
  yacl::math::MPInt::MulMod(tv2, xd, kMp25519, &gxd);  // 6. gxd = xd^3

  yacl::math::MPInt gx1;
  yacl::math::MPInt::MulMod(kMp25519J, tv1, kMp25519,
                            &gx1);  // 7. gx1 = J * tv1

  gx1 = gx1.MulMod(x1n, kMp25519);  // 8. gx1 = gx1 * x1n
  gx1 = gx1.AddMod(tv2, kMp25519);  // 9. gx1 = gx1 + tv2
  gx1 = gx1.MulMod(x1n, kMp25519);  // 10. gx1 = gx1 * x1n

  yacl::math::MPInt tv3;
  yacl::math::MPInt::MulMod(gxd, gxd, kMp25519, &tv3);  // 11. tv3 = gxd^2

  yacl::math::MPInt::MulMod(tv3, tv3, kMp25519, &tv2);  // 12. tv2 = tv3^2

  tv3 = tv3.MulMod(gxd, kMp25519);  // 13. tv3 = tv3 * gxd
  tv3 = tv3.MulMod(gx1, kMp25519);  // 14. tv3 = tv3 * gx1
  tv2 = tv2.MulMod(tv3, kMp25519);  // 15. tv2 = tv2 * tv3

  yacl::math::MPInt y11;
  yacl::math::MPInt::PowMod(tv2, kMpC4, kMp25519, &y11);  // 16. y11 = tv2^c4
  y11 = y11.MulMod(tv3, kMp25519);                        // 17. y11 = y11 * tv3

  yacl::math::MPInt y12 =
      y11.MulMod(kMpSqrtm1, kMp25519);                  // 18. y12 = y11 * c3
  yacl::math::MPInt::MulMod(y11, y11, kMp25519, &tv2);  // 19. tv2 = y11^2

  tv2 = tv2.MulMod(gxd, kMp25519);  // 20. tv2 = tv2 * gxd
  bool e1 = (tv2 == gx1);           // 21. e1 = tv2 == gx1

  yacl::math::MPInt y1;  // 22. y1 = CMOV(y12, y11, e1)
  if (e1) {
    y1 = y11;
  } else {
    y1 = y12;
  }

  yacl::math::MPInt x2n = x1n.MulMod(tv1, kMp25519);  // 23. x2n = x1n * tv1
  yacl::math::MPInt y21 = y11.MulMod(u, kMp25519);    // 24. y21 = y11 * u
  y21 = y21.MulMod(kMpC2, kMp25519);                  // 25. y21 = y21 * c2
  yacl::math::MPInt y22 =
      y21.MulMod(kMpSqrtm1, kMp25519);                // 26. y22 = y21 * c3
  yacl::math::MPInt gx2 = gx1.MulMod(tv1, kMp25519);  // 27. gx2 = gx1 * tv1

  yacl::math::MPInt::MulMod(y21, y21, kMp25519, &tv2);  // 28. tv2 = y21^2
  tv2 = tv2.MulMod(gxd, kMp25519);                      // 29. tv2 = tv2 * gxd

  bool e2 = (tv2 == gx2);  // 30. e2 = tv2 == gx2
  yacl::math::MPInt y2;    // 31. y2 = CMOV(y22, y21, e2)
  if (e2) {
    y2 = y21;
  } else {
    y2 = y22;
  }
  yacl::math::MPInt::MulMod(y1, y1, kMp25519, &tv2);  // 32. tv2 = y1^2
  tv2 = tv2.MulMod(gxd, kMp25519);                    // 33. tv2 = tv2 * gxd

  bool e3 = (tv2 == gx1);  // 34. e3 = tv2 == gx1

  yacl::math::MPInt xn;  // 35. xn = CMOV(x2n, x1n, e3)
  yacl::math::MPInt y;   // 36. y = CMOV(y2, y1, e3)
  if (e3) {
    xn = x1n;
    y = y1;
  } else {
    xn = x2n;
    y = y2;
  }

  bool e4 = Sgn0(y) == 1;  // 37. e4 = sgn0(y)==1

  if (e3 ^ e4) {
    y.NegateInplace();
  }
  if (y.IsNegative()) {
    y = y.AddMod(kMp25519, kMp25519);
  }
  yacl::math::MPInt xd1;
  yacl::math::MPInt::InvertMod(xd, kMp25519, &xd1);
  xn = xn.MulMod(xd1, kMp25519);

  std::vector<uint8_t> xvec(kCurve25519KeySize);
  std::vector<uint8_t> yvec(kCurve25519KeySize);

  MPIntToBytesWithPad(xvec, kCurve25519KeySize, xn);
  MPIntToBytesWithPad(yvec, kCurve25519KeySize, y);

  return std::make_pair(xvec, yvec);
}

// RFC9380 F.3.  Elligator 2 Method  map_to_curve_elligator2
[[maybe_unused]] std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
MapToCurveElligator2(yacl::ByteContainerView ubuf) {
  size_t J = k25519J;

  // size_t K = 1;
  //  Z: 2
  yacl::math::MPInt Z(2);
  // h_eff: 8
  // c1 = J / K
  // c2 = 1 / K^2
  yacl::math::MPInt c1(J);
  yacl::math::MPInt c2(1);

  yacl::math::MPInt u;
  u.FromMagBytes(ubuf, yacl::Endian::big);

  yacl::math::MPInt tmp;
  yacl::math::MPInt neg1(1);
  neg1.NegateInplace();

  yacl::math::MPInt tv1;
  yacl::math::MPInt::MulMod(u, u, kMp25519, &tv1);  // tv1 = u^2

  yacl::math::MPInt::MulMod(tv1, Z, kMp25519, &tmp);  // tv1 = Z * tv1
  tv1 = tmp;

  if (tv1 == neg1) {  // # if tv1 == -1, set tv1 = 0
    tv1 = yacl::math::MPInt(0);
  }
  yacl::math::MPInt x2 = tv1.AddMod(kMp1, kMp25519);
  yacl::math::MPInt x1 = x2.InvertMod(kMp25519);
  yacl::math::MPInt neg_c1;
  c1.Negate(&neg_c1);

  x2 = x1;
  x1 = x2.MulMod(neg_c1, kMp25519);  // x1 = -c1 * x1;

  yacl::math::MPInt gx1 = x1.AddMod(c1, kMp25519);  // gx1 = x1 + c1
  x2 = gx1;

  gx1 = x2.MulMod(x1, kMp25519);  // gx1 = gx1 * x1
  x2 = gx1;
  gx1 = gx1.AddMod(c2, kMp25519);  // gx1 = gx1 + c2
  x2 = gx1;
  gx1 = x2.MulMod(x1, kMp25519);  // gx1 = gx1 + c2
  yacl::math::MPInt neg_x1;
  x1.Negate(&neg_x1);

  x2 = neg_x1.AddMod(neg_c1, kMp25519);  // x2 = -x1 - c1;

  tmp = gx1;
  yacl::math::MPInt gx2 = tmp.MulMod(tv1, kMp25519);  // gx2 = tv1 * gx1
  bool e2 = IsSquare(gx1, kMp25519);

  yacl::math::MPInt xmp;

  yacl::math::MPInt y2;
  if (e2) {
    xmp = x1;
    y2 = gx1;
  } else {
    xmp = x2;
    y2 = gx2;
  }

  yacl::math::MPInt ymp = Curve25519Sqrt(y2, kMp25519);  // y = sqrt(y2)

  bool e3 = Sgn0(ymp);

  if (e2 ^ e3) {
    ymp.NegateInplace();
    if (ymp.IsNegative()) {
      ymp = ymp.AddMod(kMp25519, kMp25519);
    }
  }

  std::vector<uint8_t> xvec(kCurve25519KeySize);
  std::vector<uint8_t> yvec(kCurve25519KeySize);

  MPIntToBytesWithPad(xvec, kCurve25519KeySize, xmp);
  MPIntToBytesWithPad(yvec, kCurve25519KeySize, ymp);

  return std::make_pair(xvec, yvec);
}

inline yacl::math::MPInt ToMpInt(yacl::ByteContainerView msgx) {
  yacl::math::MPInt mp_u;
  mp_u.FromMagBytes(msgx, yacl::Endian::big);

  return mp_u;
}

// https://martin.kleppmann.com/papers/curve25519.pdf
// 4.2 P18  affine coordinates point add
[[maybe_unused]] std::pair<std::vector<uint8_t>, std::vector<uint8_t>> PointAdd(
    yacl::ByteContainerView pxbuf, yacl::ByteContainerView pybuf,
    yacl::ByteContainerView qxbuf, yacl::ByteContainerView qybuf) {
  YACL_ENFORCE((std::memcmp(pxbuf.data(), qxbuf.data(), pxbuf.size()) != 0) ||
               (std::memcmp(pybuf.data(), qybuf.data(), pybuf.size()) != 0));

  yacl::math::MPInt px = ToMpInt(pxbuf);
  yacl::math::MPInt py = ToMpInt(pybuf);
  yacl::math::MPInt qx = ToMpInt(qxbuf);
  yacl::math::MPInt qy = ToMpInt(qybuf);

  // lambda = (y2-y1)/(x2-x2)
  yacl::math::MPInt s1 = qx.SubMod(px, kMp25519);  //  x2-x1
  yacl::math::MPInt s2 = qy.SubMod(py, kMp25519);  // y2-y1

  yacl::math::MPInt d = s1.InvertMod(kMp25519);
  yacl::math::MPInt l = s2.MulMod(d, kMp25519);  // (y2-y1)/(x2-x1)

  yacl::math::MPInt l2 = l.MulMod(l, kMp25519);  // (y2-y1)/(x2-x1) ^2

  // x coordinate
  yacl::math::MPInt t1 =
      l2.SubMod(kMp25519J, kMp25519);  // (y2-y1)/(x2-x1) ^2-A-x1-x2
  yacl::math::MPInt t2 = t1.SubMod(px, kMp25519);
  yacl::math::MPInt tx = t2.SubMod(qx, kMp25519);
  if (tx.IsNegative()) {
    tx = tx.AddMod(kMp25519, kMp25519);
  }

  // y coordinate
  yacl::math::MPInt l3 = l2.MulMod(l, kMp25519);  // (y2-y1)/(x2-x1) ^3
  t1 = px.MulMod(kMp2, kMp25519);                 // 2*x1
  t2 = t1.AddMod(qx, kMp25519);                   // 2*x1 + x2
  t1 = t2.AddMod(kMp25519J, kMp25519);            // 2*x1 + x2 + A
  t2 = t1.MulMod(l, kMp25519);                    // (2*x1 + x2 + A) * lambda
  t1 = t2.SubMod(l3, kMp25519);  // (2*x1 + x2 + A) * lambda - labmba^3
  yacl::math::MPInt ty =
      t1.SubMod(py, kMp25519);  // (2*x1 + x2 + A) * lambda - labmba^3 -y1

  if (ty.IsNegative()) {
    ty = ty.AddMod(kMp25519, kMp25519);
  }

  std::vector<uint8_t> xbuf(kCurve25519KeySize);
  std::vector<uint8_t> ybuf(kCurve25519KeySize);

  MPIntToBytesWithPad(xbuf, kCurve25519KeySize, tx);
  MPIntToBytesWithPad(ybuf, kCurve25519KeySize, ty);

  return std::make_pair(xbuf, ybuf);
}

// affine coordinates point double
[[maybe_unused]] std::pair<std::vector<uint8_t>, std::vector<uint8_t>> PointDbl(
    yacl::ByteContainerView pxbuf, yacl::ByteContainerView pybuf) {
  yacl::math::MPInt px = ToMpInt(pxbuf);
  yacl::math::MPInt py = ToMpInt(pybuf);

  yacl::math::MPInt px2 = px.MulMod(px, kMp25519);     // x^2
  yacl::math::MPInt px3 = px2.MulMod(kMp3, kMp25519);  // 3*x^2

  yacl::math::MPInt ax = px.MulMod(kMp25519J, kMp25519);  // x*A
  yacl::math::MPInt ax2 = ax.MulMod(kMp2, kMp25519);      // 2*x*A

  px2 = px3.AddMod(ax2, kMp25519);  // 3*x^2 + 2*x*A
  ax = px2.AddMod(kMp1, kMp25519);  // 3*x^2 + 2*x*A +1

  yacl::math::MPInt y2 = py.MulMod(kMp2, kMp25519);  // 2*y

  yacl::math::MPInt d = y2.InvertMod(kMp25519);

  yacl::math::MPInt l = ax.MulMod(d, kMp25519);  // 3*x^2 + 2*x*A +1 / 2*y

  yacl::math::MPInt l2 = l.PowMod(kMp2, kMp25519);  // lambda^2
  yacl::math::MPInt l3 = l.PowMod(kMp3, kMp25519);  // lambda^3

  yacl::math::MPInt xt1 = l2.SubMod(kMp25519J, kMp25519);  // lambda^2-A
  yacl::math::MPInt x2 = px.MulMod(kMp2, kMp25519);        // 2*x
  yacl::math::MPInt tx = xt1.SubMod(x2, kMp25519);         // lambda^2-A-2*x

  yacl::math::MPInt x3 = px.MulMod(kMp3, kMp25519);
  xt1 = x3.AddMod(kMp25519J, kMp25519);
  d = xt1.MulMod(l, kMp25519);

  xt1 = d.SubMod(l3, kMp25519);
  yacl::math::MPInt ty = xt1.SubMod(py, kMp25519);

  std::vector<uint8_t> xbuf(kCurve25519KeySize);
  std::vector<uint8_t> ybuf(kCurve25519KeySize);

  MPIntToBytesWithPad(xbuf, kCurve25519KeySize, tx);
  MPIntToBytesWithPad(ybuf, kCurve25519KeySize, ty);

  return std::make_pair(xbuf, ybuf);
}

[[maybe_unused]] std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
PointClearCofactor(yacl::ByteContainerView pxbuf,
                   yacl::ByteContainerView pybuf) {
  // [2]P
  std::vector<uint8_t> x2buf(kCurve25519KeySize);
  std::vector<uint8_t> y2buf(kCurve25519KeySize);
  std::tie(x2buf, y2buf) = PointDbl(pxbuf, pybuf);

  // [4]P
  std::vector<uint8_t> x4buf(kCurve25519KeySize);
  std::vector<uint8_t> y4buf(kCurve25519KeySize);
  std::tie(x4buf, y4buf) = PointDbl(x2buf, y2buf);

  std::vector<uint8_t> xbuf(kCurve25519KeySize);
  std::vector<uint8_t> ybuf(kCurve25519KeySize);

  // [8]P
  std::tie(xbuf, ybuf) = PointDbl(x4buf, y4buf);

  return std::make_pair(xbuf, ybuf);
}

crypto::EcPoint HashToCurveCurve25519(yacl::ByteContainerView buffer,
                                      const std::string &dst) {
  YACL_ENFORCE((dst.size() >= 16) && (dst.size() <= 255),
               "domain separation tag length: {} not in 16B-255B", dst.size());

  std::vector<std::vector<uint8_t>> u =
      HashToField(buffer, 2, 48, kCurve25519KeySize,
                  crypto::HashAlgorithm::SHA512, kMp25519, dst);

  std::vector<uint8_t> q0x(kCurve25519KeySize);
  std::vector<uint8_t> q0y(kCurve25519KeySize);
  std::vector<uint8_t> q1x(kCurve25519KeySize);
  std::vector<uint8_t> q1y(kCurve25519KeySize);

  std::vector<uint8_t> px(kCurve25519KeySize);
  std::vector<uint8_t> py(kCurve25519KeySize);

  std::tie(q0x, q0y) = MapToCurveG2(u[0]);
  std::tie(q1x, q1y) = MapToCurveG2(u[1]);

  std::tie(px, py) = PointAdd(q0x, q0y, q1x, q1y);
  std::tie(px, py) = PointClearCofactor(px, py);

  yacl::math::MPInt x =
      DeserializeMPInt(px, kCurve25519KeySize, yacl::Endian::big);
  yacl::math::MPInt y =
      DeserializeMPInt(py, kCurve25519KeySize, yacl::Endian::big);

  crypto::AffinePoint p(x, y);

  return p;
}

crypto::EcPoint EncodeToCurveCurve25519(yacl::ByteContainerView buffer,
                                        const std::string &dst) {
  YACL_ENFORCE((dst.size() >= 16) && (dst.size() <= 255),
               "domain separation tag length: {} not in 16B-255B", dst.size());

  std::vector<std::vector<uint8_t>> u =
      HashToField(buffer, 1, 48, kCurve25519KeySize,
                  crypto::HashAlgorithm::SHA512, kMp25519, dst);

  std::vector<uint8_t> qx(kCurve25519KeySize);
  std::vector<uint8_t> qy(kCurve25519KeySize);

  std::tie(qx, qy) = MapToCurveG2(u[0]);

  std::tie(qx, qy) = PointClearCofactor(qx, qy);

  yacl::math::MPInt x =
      DeserializeMPInt(qx, kCurve25519KeySize, yacl::Endian::big);
  yacl::math::MPInt y =
      DeserializeMPInt(qy, kCurve25519KeySize, yacl::Endian::big);

  crypto::AffinePoint p(x, y);

  return p;
}
}  // namespace yacl
