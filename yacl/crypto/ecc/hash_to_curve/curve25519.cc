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
#include "yacl/crypto/hash/ssl_hash.h"
#include "yacl/math/mpint/mp_int.h"
#include "yacl/utils/spi/type_traits.h"

namespace yacl {

constexpr int kEccKeySize = 32;

// y^2 = x^3 + 486662 * x^2 + x
// p = 2^255 - 19
constexpr std::array<uint8_t, kEccKeySize> p_bytes = {
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f};

// c1 = (p+3)/8
constexpr std::array<uint8_t, kEccKeySize> c1_bytes = {
    0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf};

// c2 = 2^c1
constexpr std::array<uint8_t, kEccKeySize> c2_bytes = {
    0xb1, 0xa0, 0xe,  0x4a, 0x27, 0x1b, 0xee, 0xc4, 0x78, 0xe4, 0x2f,
    0xad, 0x6,  0x18, 0x43, 0x2f, 0xa7, 0xd7, 0xfb, 0x3d, 0x99, 0x0,
    0x4d, 0x2b, 0xb,  0xdf, 0xc1, 0x4f, 0x80, 0x24, 0x83, 0x2b};

// c3 = sqrt(p-1)
constexpr std::array<uint8_t, kEccKeySize> sqrtm1_bytes = {
    0x3d, 0x5f, 0xf1, 0xb5, 0xd8, 0xe4, 0x11, 0x3b, 0x87, 0x1b, 0xd0,
    0x52, 0xf9, 0xe7, 0xbc, 0xd0, 0x58, 0x28, 0x4,  0xc2, 0x66, 0xff,
    0xb2, 0xd4, 0xf4, 0x20, 0x3e, 0xb0, 0x7f, 0xdb, 0x7c, 0x54};

// c4 = (p-5)/8
constexpr std::array<uint8_t, kEccKeySize> c4_bytes = {
    0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf};

yacl::math::MPInt DeserializeMPIntCurve25519(
    yacl::ByteContainerView buffer,
    yacl::Endian endian = yacl::Endian::native) {
  YACL_ENFORCE(buffer.size() == kEccKeySize);
  yacl::math::MPInt mp;

  mp.FromMagBytes(buffer, endian);

  return mp;
}

void MPIntToBytesWithPad(unsigned char *buf, size_t buf_len,
                         const yacl::math::MPInt &mp) {
  YACL_ENFORCE(buf_len == kEccKeySize);
  yacl::Buffer mpbuf = mp.ToMagBytes(yacl::Endian::big);
  YACL_ENFORCE((size_t)(mpbuf.size()) <= buf_len, "{},{}", mpbuf.size(),
               buf_len);

  std::memcpy(buf + (kEccKeySize - mpbuf.size()), mpbuf.data(), mpbuf.size());
}

constexpr size_t k25519J = 486662;
const yacl::math::MPInt kMp1(1);
const yacl::math::MPInt kMp2(2);
const yacl::math::MPInt kMp3(3);
const yacl::math::MPInt kMp8(8);
const yacl::math::MPInt kMp25519J(k25519J);
const yacl::math::MPInt kMp25519 =
    DeserializeMPIntCurve25519(p_bytes, yacl::Endian::little);
const yacl::math::MPInt kMpSqrtm1 =
    DeserializeMPIntCurve25519(sqrtm1_bytes, yacl::Endian::little);

const yacl::math::MPInt kMpC1 =
    DeserializeMPIntCurve25519(c1_bytes, yacl::Endian::little);
const yacl::math::MPInt kMpC2 =
    DeserializeMPIntCurve25519(c2_bytes, yacl::Endian::little);
const yacl::math::MPInt kMpC4 =
    DeserializeMPIntCurve25519(c4_bytes, yacl::Endian::little);

// rfc8017 4.1 I2OSP
// I2OSP - Integer-to-Octet-String primitive
// Input:
//   x        nonnegative integer to be converted
//   xlen     intended length of the resulting octet string
// Output:
//   X corresponding octet string of length xLen
// Error : "integer too large"
std::vector<uint8_t> I2OSP(size_t x, size_t xlen) {
  YACL_ENFORCE(x < std::pow(256, xlen));

  yacl::ByteContainerView xbytes(&x, xlen);

  std::vector<uint8_t> ret(xlen);
  std::memcpy(ret.data(), xbytes.data(), xlen);

  if (xlen > 1) {
    std::reverse(ret.begin(), ret.end());
  }
  return ret;
}

// RFC9380 5.3.1.  expand_message_xmd
std::vector<uint8_t> ExpandMessageXmdCurve25519(yacl::ByteContainerView msg,
                                                yacl::ByteContainerView dst,
                                                size_t len_in_bytes) {
  yacl::crypto::SslHash hash_sha512(yacl::crypto::HashAlgorithm::SHA512);
  size_t b_in_bytes = hash_sha512.DigestSize();
  size_t s_in_bytes = 128;

  size_t ell = std::ceil(static_cast<double>(len_in_bytes) / b_in_bytes);

  YACL_ENFORCE(ell <= 255);
  YACL_ENFORCE(len_in_bytes <= 65535);
  YACL_ENFORCE(dst.size() >= 16);
  YACL_ENFORCE(dst.size() <= 255);

  std::vector<uint8_t> dst_prime(dst.size());
  std::memcpy(dst_prime.data(), dst.data(), dst_prime.size());
  std::vector<uint8_t> dstlen_octet = I2OSP(dst.size(), 1);
  dst_prime.insert(dst_prime.end(), dstlen_octet.begin(), dstlen_octet.end());

  std::vector<uint8_t> z_pad(s_in_bytes);

  std::vector<uint8_t> l_i_b_str = I2OSP(len_in_bytes, 2);

  hash_sha512.Update(z_pad);
  hash_sha512.Update(msg);
  hash_sha512.Update(l_i_b_str);
  std::vector<uint8_t> z1(1);
  hash_sha512.Update(z1);
  hash_sha512.Update(dst_prime);

  std::vector<uint8_t> b_0 = hash_sha512.CumulativeHash();

  hash_sha512.Reset();
  // b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
  hash_sha512.Update(b_0);
  z1[0] = 1;
  hash_sha512.Update(z1);
  hash_sha512.Update(dst_prime);
  std::vector<uint8_t> b_1 = hash_sha512.CumulativeHash();
  hash_sha512.Reset();

  std::vector<uint8_t> ret;

  ret.insert(ret.end(), b_1.begin(), b_1.end());

  std::vector<uint8_t> b_i(b_0.size());
  std::memcpy(b_i.data(), b_1.data(), b_1.size());

  for (size_t i = 2; i <= ell; i++) {
    for (size_t j = 0; j < b_i.size(); ++j) {
      b_i[j] = b_i[j] ^ b_0[j];
    }
    hash_sha512.Update(b_i);
    z1[0] = i;
    hash_sha512.Update(z1);
    hash_sha512.Update(dst_prime);
    b_i = hash_sha512.CumulativeHash();
    ret.insert(ret.end(), b_i.begin(), b_i.end());
    hash_sha512.Reset();
  }

  ret.resize(len_in_bytes);
  return ret;
}

// RFC9380 5.2.  hash_to_field Implementation
std::vector<std::vector<uint8_t>> HashToFieldCurve25519(
    yacl::ByteContainerView msg, size_t count, const std::string &dst) {
  size_t L = std::ceil(static_cast<double>(256 + 128) / 8);

  size_t len_in_bytes = count * L;

  std::vector<uint8_t> uniform_bytes =
      ExpandMessageXmdCurve25519(msg, dst, len_in_bytes);

  std::vector<std::vector<uint8_t>> ret(count);

  for (size_t i = 0; i < count; ++i) {
    size_t elm_offset = L * i;
    absl::Span<uint8_t> data = absl::MakeSpan(&uniform_bytes[elm_offset], L);

    yacl::math::MPInt e_j;
    e_j.FromMagBytes(data, yacl::Endian::big);

    yacl::math::MPInt e_jp = e_j.Mod(kMp25519);

    ret[i].resize(kEccKeySize);
    MPIntToBytesWithPad(ret[i].data(), kEccKeySize, e_jp);
  }

  return ret;
}

bool IsSquare(const yacl::math::MPInt &v, const yacl::math::MPInt &mod) {
  yacl::math::MPInt t1 = mod.SubMod(kMp1, mod);  // mod - 1
  yacl::math::MPInt t2;
  yacl::math::MPInt::InvertMod(kMp2, mod, &t2);  // inverse 2

  yacl::math::MPInt t3 = t1.MulMod(t2, mod);  // (q-1)/2
  yacl::math::MPInt t4 = v.PowMod(t3, mod);   // x^((q-1)/2)

  if (t4.IsOne() || t4.IsZero()) {
    return true;
  }
  return false;
}

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

bool Curve25519Sgn0(const yacl::math::MPInt &v) {
  yacl::math::MPInt c;
  yacl::math::MPInt d;
  yacl::math::MPInt::Div(v, kMp2, &c, &d);

  bool ret = 1;
  if (d.IsZero()) {
    ret = 0;
  }

  return ret;
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

  bool e4 = Curve25519Sgn0(y) == 1;  // 37. e4 = sgn0(y)==1

  if (e3 ^ e4) {
    y.NegateInplace();
  }
  if (y.IsNegative()) {
    y = y.AddMod(kMp25519, kMp25519);
  }
  yacl::math::MPInt xd1;
  yacl::math::MPInt::InvertMod(xd, kMp25519, &xd1);
  xn = xn.MulMod(xd1, kMp25519);

  std::vector<uint8_t> xvec(kEccKeySize);
  std::vector<uint8_t> yvec(kEccKeySize);

  MPIntToBytesWithPad(xvec.data(), xvec.size(), xn);
  MPIntToBytesWithPad(yvec.data(), yvec.size(), y);

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

  bool e3 = Curve25519Sgn0(ymp);

  if (e2 ^ e3) {
    ymp.NegateInplace();
    if (ymp.IsNegative()) {
      ymp = ymp.AddMod(kMp25519, kMp25519);
    }
  }

  std::vector<uint8_t> xvec(kEccKeySize);
  std::vector<uint8_t> yvec(kEccKeySize);

  MPIntToBytesWithPad(xvec.data(), kEccKeySize, xmp);
  MPIntToBytesWithPad(yvec.data(), kEccKeySize, ymp);

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

  std::vector<uint8_t> xbuf(kEccKeySize);
  std::vector<uint8_t> ybuf(kEccKeySize);

  MPIntToBytesWithPad(xbuf.data(), kEccKeySize, tx);
  MPIntToBytesWithPad(ybuf.data(), kEccKeySize, ty);

  return std::make_pair(xbuf, ybuf);
}

// point add return x coordinate
[[maybe_unused]] yacl::crypto::Array32 PointAddX(
    yacl::ByteContainerView pxbuf, yacl::ByteContainerView pybuf,
    yacl::ByteContainerView qxbuf, yacl::ByteContainerView qybuf) {
  YACL_ENFORCE((std::memcmp(pxbuf.data(), qxbuf.data(), pxbuf.size()) != 0) ||
               (std::memcmp(pybuf.data(), qybuf.data(), pybuf.size()) != 0));

  yacl::math::MPInt px = ToMpInt(pxbuf);
  yacl::math::MPInt py = ToMpInt(pybuf);
  yacl::math::MPInt qx = ToMpInt(qxbuf);
  yacl::math::MPInt qy = ToMpInt(qybuf);

  // lambda = (y2-y1)/(x2-x2)
  yacl::math::MPInt s1 = qx.SubMod(px, kMp25519);  // x2-x1
  yacl::math::MPInt s2 = qy.SubMod(py, kMp25519);  // y2-y1

  yacl::math::MPInt d = s1.InvertMod(kMp25519);  // 1/(x2-x1)
  yacl::math::MPInt l = s2.MulMod(d, kMp25519);  // (y2-y1)/(x2-x1)

  // x coordinate
  yacl::math::MPInt l2 = l.MulMod(l, kMp25519);  // (y2-y1)/(x2-x1) ^2

  yacl::math::MPInt t1 =
      l2.SubMod(kMp25519J, kMp25519);  // (y2-y1)/(x2-x1) ^2-A-x1-x2
  yacl::math::MPInt t2 = t1.SubMod(px, kMp25519);
  yacl::math::MPInt tx = t2.SubMod(qx, kMp25519);
  if (tx.IsNegative()) {
    tx = tx.AddMod(kMp25519, kMp25519);
  }

  yacl::crypto::Array32 xbuf = {0};

  MPIntToBytesWithPad(xbuf.data(), xbuf.size(), tx);

  return xbuf;
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

  std::vector<uint8_t> xbuf(kEccKeySize);
  std::vector<uint8_t> ybuf(kEccKeySize);

  MPIntToBytesWithPad(xbuf.data(), kEccKeySize, tx);
  MPIntToBytesWithPad(ybuf.data(), kEccKeySize, ty);

  return std::make_pair(xbuf, ybuf);
}

// https://martin.kleppmann.com/papers/curve25519.pdf
// Projective formulas for point doubling
// 4.4 P23 formulas 25
[[maybe_unused]] yacl::crypto::Array32 PointDblProjective(
    yacl::ByteContainerView pxbuf) {
  yacl::math::MPInt px = ToMpInt(pxbuf);

  yacl::math::MPInt px2 = px.MulMod(px, kMp25519);       // px2 = px^2
  yacl::math::MPInt px21 = px2.SubMod(kMp1, kMp25519);   // px21 = px^2-1
  yacl::math::MPInt px22 = px21.MulMod(px21, kMp25519);  // px22 = px21^2

  yacl::math::MPInt pxa = px.MulMod(kMp25519J, kMp25519);  // A*X
  yacl::math::MPInt pz1 =
      px2.AddMod(pxa, kMp25519).AddMod(kMp1, kMp25519);  // x^2+Axz+z^2
  yacl::math::MPInt pz2 = pz1.MulMod(px, kMp25519);      // x*(x^2+Axz+z^2)

  pz1 = pz2.MulMod(yacl::math::MPInt(4), kMp25519);

  yacl::math::MPInt::InvertMod(pz1, kMp25519, &pz2);

  px = px22.MulMod(pz2, kMp25519);

  yacl::crypto::Array32 xbuf = {0};

  MPIntToBytesWithPad(xbuf.data(), xbuf.size(), px);

  return xbuf;
}

[[maybe_unused]] yacl::crypto::Array32 PointClearCofactorProjective(
    yacl::ByteContainerView pxbuf) {
  // [2]P
  auto x2buf = PointDblProjective(pxbuf);
  // [4]P
  auto x4buf = PointDblProjective(x2buf);
  // [8]P
  auto x8buf = PointDblProjective(x4buf);

  return x8buf;
}

[[maybe_unused]] std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
PointClearCofactor(yacl::ByteContainerView pxbuf,
                   yacl::ByteContainerView pybuf) {
  // [2]P
  std::vector<uint8_t> x2buf(kEccKeySize);
  std::vector<uint8_t> y2buf(kEccKeySize);
  std::tie(x2buf, y2buf) = PointDbl(pxbuf, pybuf);

  // [4]P
  std::vector<uint8_t> x4buf(kEccKeySize);
  std::vector<uint8_t> y4buf(kEccKeySize);
  std::tie(x4buf, y4buf) = PointDbl(x2buf, y2buf);

  std::vector<uint8_t> xbuf(kEccKeySize);
  std::vector<uint8_t> ybuf(kEccKeySize);

  // [8]P
  std::tie(xbuf, ybuf) = PointDbl(x4buf, y4buf);

  return std::make_pair(xbuf, ybuf);
}

crypto::EcPoint EncodeToCurveCurve25519(yacl::ByteContainerView buffer,
                                        const std::string &dst) {
  YACL_ENFORCE((dst.size() >= 16) && (dst.size() <= 255),
               "domain separation tag length: {} not in 16B-255B", dst.size());

  std::vector<std::vector<uint8_t>> u = HashToFieldCurve25519(buffer, 2, dst);

  std::vector<uint8_t> q0x(kEccKeySize);
  std::vector<uint8_t> q0y(kEccKeySize);
  std::vector<uint8_t> q1x(kEccKeySize);
  std::vector<uint8_t> q1y(kEccKeySize);

  std::vector<uint8_t> px(kEccKeySize);
  std::vector<uint8_t> py(kEccKeySize);

  std::tie(q0x, q0y) = MapToCurveG2(u[0]);
  std::tie(q1x, q1y) = MapToCurveG2(u[1]);

  std::tie(px, py) = PointAdd(q0x, q0y, q1x, q1y);
  std::tie(px, py) = PointClearCofactor(px, py);

  yacl::math::MPInt x = DeserializeMPIntCurve25519(px, yacl::Endian::big);
  yacl::math::MPInt y = DeserializeMPIntCurve25519(py, yacl::Endian::big);

  crypto::AffinePoint p(x, y);

  return p;
}

}  // namespace yacl
