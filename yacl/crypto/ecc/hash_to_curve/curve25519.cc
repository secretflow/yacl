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

#include "yacl/crypto/ecc/ec_point.h"
#include "yacl/crypto/ecc/hash_to_curve/hash_to_curve_util.h"
#include "yacl/math/mpint/mp_int.h"
#include "yacl/utils/spi/type_traits.h"

namespace yacl {

// RFC9380 G.2.  Elligator 2 Method  map_to_curve_elligator2
[[maybe_unused]] std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
MapToCurveG2(yacl::ByteContainerView ubuf, HashToCurveCtx &ctx) {
  yacl::math::MPInt kMp25519 = ctx.aux["p"];
  yacl::math::MPInt kMpA = ctx.aux["a"];
  yacl::math::MPInt kMpC2 = ctx.aux["c2"];
  yacl::math::MPInt kMpC4 = ctx.aux["c4"];
  yacl::math::MPInt kMpSqrtm1 = ctx.aux["sqrtm1"];

  YACL_ENFORCE(ubuf.size() > 0);

  yacl::math::MPInt u;
  u.FromMagBytes(ubuf, yacl::Endian::big);

  yacl::math::MPInt tv1;
  yacl::math::MPInt::MulMod(u, u, kMp25519, &tv1);  // 1. tv1 = u^2

  tv1 = tv1.MulMod(kMp2, kMp25519);  // 2. tv1 = 2*tv1

  yacl::math::MPInt xd;
  yacl::math::MPInt::AddMod(tv1, kMp1, kMp25519, &xd);  // 3. xd = tv1 + 1

  yacl::math::MPInt x1n = kMpA;
  x1n.NegateInplace();  // 4. x1n = -J

  yacl::math::MPInt tv2;
  yacl::math::MPInt::MulMod(xd, xd, kMp25519, &tv2);  // 5. tv2 = xd^2

  yacl::math::MPInt gxd;
  yacl::math::MPInt::MulMod(tv2, xd, kMp25519, &gxd);  // 6. gxd = xd^3

  yacl::math::MPInt gx1;
  yacl::math::MPInt::MulMod(kMpA, tv1, kMp25519,
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

  std::vector<uint8_t> xvec(ctx.key_size);
  std::vector<uint8_t> yvec(ctx.key_size);

  MPIntToBytesWithPad(xvec, ctx.key_size, xn);
  MPIntToBytesWithPad(yvec, ctx.key_size, y);

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
    yacl::ByteContainerView qxbuf, yacl::ByteContainerView qybuf,
    HashToCurveCtx &ctx) {
  yacl::math::MPInt kMp25519 = ctx.aux["p"];
  yacl::math::MPInt kMpA = ctx.aux["a"];

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
      l2.SubMod(kMpA, kMp25519);  // (y2-y1)/(x2-x1) ^2-A-x1-x2
  yacl::math::MPInt t2 = t1.SubMod(px, kMp25519);
  yacl::math::MPInt tx = t2.SubMod(qx, kMp25519);
  if (tx.IsNegative()) {
    tx = tx.AddMod(kMp25519, kMp25519);
  }

  // y coordinate
  yacl::math::MPInt l3 = l2.MulMod(l, kMp25519);  // (y2-y1)/(x2-x1) ^3
  t1 = px.MulMod(kMp2, kMp25519);                 // 2*x1
  t2 = t1.AddMod(qx, kMp25519);                   // 2*x1 + x2
  t1 = t2.AddMod(kMpA, kMp25519);                 // 2*x1 + x2 + A
  t2 = t1.MulMod(l, kMp25519);                    // (2*x1 + x2 + A) * lambda
  t1 = t2.SubMod(l3, kMp25519);  // (2*x1 + x2 + A) * lambda - labmba^3
  yacl::math::MPInt ty =
      t1.SubMod(py, kMp25519);  // (2*x1 + x2 + A) * lambda - labmba^3 -y1

  if (ty.IsNegative()) {
    ty = ty.AddMod(kMp25519, kMp25519);
  }

  std::vector<uint8_t> xbuf(ctx.key_size);
  std::vector<uint8_t> ybuf(ctx.key_size);

  MPIntToBytesWithPad(xbuf, ctx.key_size, tx);
  MPIntToBytesWithPad(ybuf, ctx.key_size, ty);

  return std::make_pair(xbuf, ybuf);
}

// affine coordinates point double
[[maybe_unused]] std::pair<std::vector<uint8_t>, std::vector<uint8_t>> PointDbl(
    yacl::ByteContainerView pxbuf, yacl::ByteContainerView pybuf,
    HashToCurveCtx &ctx) {
  yacl::math::MPInt kMp25519 = ctx.aux["p"];
  yacl::math::MPInt kMpA = ctx.aux["a"];
  yacl::math::MPInt kMp3(3);

  yacl::math::MPInt px = ToMpInt(pxbuf);
  yacl::math::MPInt py = ToMpInt(pybuf);

  yacl::math::MPInt px2 = px.MulMod(px, kMp25519);     // x^2
  yacl::math::MPInt px3 = px2.MulMod(kMp3, kMp25519);  // 3*x^2

  yacl::math::MPInt ax = px.MulMod(kMpA, kMp25519);   // x*A
  yacl::math::MPInt ax2 = ax.MulMod(kMp2, kMp25519);  // 2*x*A

  px2 = px3.AddMod(ax2, kMp25519);  // 3*x^2 + 2*x*A
  ax = px2.AddMod(kMp1, kMp25519);  // 3*x^2 + 2*x*A +1

  yacl::math::MPInt y2 = py.MulMod(kMp2, kMp25519);  // 2*y

  yacl::math::MPInt d = y2.InvertMod(kMp25519);

  yacl::math::MPInt l = ax.MulMod(d, kMp25519);  // 3*x^2 + 2*x*A +1 / 2*y

  yacl::math::MPInt l2 = l.PowMod(kMp2, kMp25519);  // lambda^2
  yacl::math::MPInt l3 = l.PowMod(kMp3, kMp25519);  // lambda^3

  yacl::math::MPInt xt1 = l2.SubMod(kMpA, kMp25519);  // lambda^2-A
  yacl::math::MPInt x2 = px.MulMod(kMp2, kMp25519);   // 2*x
  yacl::math::MPInt tx = xt1.SubMod(x2, kMp25519);    // lambda^2-A-2*x

  yacl::math::MPInt x3 = px.MulMod(kMp3, kMp25519);
  xt1 = x3.AddMod(kMpA, kMp25519);
  d = xt1.MulMod(l, kMp25519);

  xt1 = d.SubMod(l3, kMp25519);
  yacl::math::MPInt ty = xt1.SubMod(py, kMp25519);

  std::vector<uint8_t> xbuf(ctx.key_size);
  std::vector<uint8_t> ybuf(ctx.key_size);

  MPIntToBytesWithPad(xbuf, ctx.key_size, tx);
  MPIntToBytesWithPad(ybuf, ctx.key_size, ty);

  return std::make_pair(xbuf, ybuf);
}

[[maybe_unused]] std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
PointClearCofactor(yacl::ByteContainerView pxbuf, yacl::ByteContainerView pybuf,
                   HashToCurveCtx &ctx) {
  // [2]P
  std::vector<uint8_t> x2buf(ctx.key_size);
  std::vector<uint8_t> y2buf(ctx.key_size);
  std::tie(x2buf, y2buf) = PointDbl(pxbuf, pybuf, ctx);

  // [4]P
  std::vector<uint8_t> x4buf(ctx.key_size);
  std::vector<uint8_t> y4buf(ctx.key_size);
  std::tie(x4buf, y4buf) = PointDbl(x2buf, y2buf, ctx);

  std::vector<uint8_t> xbuf(ctx.key_size);
  std::vector<uint8_t> ybuf(ctx.key_size);

  // [8]P
  std::tie(xbuf, ybuf) = PointDbl(x4buf, y4buf, ctx);

  return std::make_pair(xbuf, ybuf);
}

crypto::EcPoint HashToCurveCurve25519(yacl::ByteContainerView buffer,
                                      const std::string &dst) {
  YACL_ENFORCE((dst.size() >= 16) && (dst.size() <= 255),
               "domain separation tag length: {} not in 16B-255B", dst.size());

  HashToCurveCtx ctx = GetHashToCurveCtxByName("Curve25519");
  std::vector<std::vector<uint8_t>> u = HashToField(buffer, 2, 48, ctx, dst);

  std::vector<uint8_t> q0x(ctx.key_size);
  std::vector<uint8_t> q0y(ctx.key_size);
  std::vector<uint8_t> q1x(ctx.key_size);
  std::vector<uint8_t> q1y(ctx.key_size);

  std::vector<uint8_t> px(ctx.key_size);
  std::vector<uint8_t> py(ctx.key_size);

  std::tie(q0x, q0y) = MapToCurveG2(u[0], ctx);
  std::tie(q1x, q1y) = MapToCurveG2(u[1], ctx);

  std::tie(px, py) = PointAdd(q0x, q0y, q1x, q1y, ctx);
  std::tie(px, py) = PointClearCofactor(px, py, ctx);

  yacl::math::MPInt x = DeserializeMPInt(px, ctx.key_size, yacl::Endian::big);
  yacl::math::MPInt y = DeserializeMPInt(py, ctx.key_size, yacl::Endian::big);

  crypto::AffinePoint p(x, y);

  return p;
}

crypto::EcPoint EncodeToCurveCurve25519(yacl::ByteContainerView buffer,
                                        const std::string &dst) {
  YACL_ENFORCE((dst.size() >= 16) && (dst.size() <= 255),
               "domain separation tag length: {} not in 16B-255B", dst.size());

  HashToCurveCtx ctx = GetHashToCurveCtxByName("Curve25519");
  std::vector<std::vector<uint8_t>> u = HashToField(buffer, 1, 48, ctx, dst);

  std::vector<uint8_t> qx(ctx.key_size);
  std::vector<uint8_t> qy(ctx.key_size);

  std::tie(qx, qy) = MapToCurveG2(u[0], ctx);

  std::tie(qx, qy) = PointClearCofactor(qx, qy, ctx);

  yacl::math::MPInt x = DeserializeMPInt(qx, ctx.key_size, yacl::Endian::big);
  yacl::math::MPInt y = DeserializeMPInt(qy, ctx.key_size, yacl::Endian::big);

  crypto::AffinePoint p(x, y);

  return p;
}
}  // namespace yacl
