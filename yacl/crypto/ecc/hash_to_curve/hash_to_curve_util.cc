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

#include "yacl/crypto/ecc/hash_to_curve/hash_to_curve_util.h"

#include <cstdint>
#include <map>
#include <vector>

#include "yacl/base/exception.h"
#include "yacl/crypto/hash/hash_interface.h"
#include "yacl/crypto/hash/ssl_hash.h"
#include "yacl/math/mpint/mp_int.h"

namespace yacl {

// RFC9380 8 Suites for Hashing
static std::map<std::string, HashToCurveCtx> kPredefinedCurveCtxs = {
    // each maps a curve name to HashToCurveCtx
    // Parameters in HashToCurveCtx is listed as follows:
    // 1. key size of current curve
    // 2. s_in_bytes in ExpandMessageXmd Function, see RFC9380 5.3.1
    // 3. hash algorithm in ExpandMessageXmd Function, see RFC9380 8
    // 4. some auxiliary parameters
    //    4.1 p: the characteristic of the field
    //    4.2 a, b: coefficient in curve equation
    //    4.3 z: a non-zero element of F meeting some criteria, see RFC3980 8
    //    4.4 and after: other auxiliary parameters, depending on the underlying
    //    function
    {"P-256",
     {32,
      64,
      crypto::HashAlgorithm::SHA256,
      {
          {"p",
           "0xffffffff000000010000000000000000"
           "00000000ffffffffffffffffffffffff"_mp},
          {"a",
           "0xffffffff000000010000000000000000"
           "00000000fffffffffffffffffffffffc"_mp},
          {"b",
           "0x5ac635d8aa3a93e7b3ebbd55769886bc"
           "651d06b0cc53b0f63bce3c3e27d2604b"_mp},
          {"z",
           "0xffffffff000000010000000000000000"
           "00000000fffffffffffffffffffffff5"_mp},
          {"c1",  // RFC9390 I.1 sqrt for q = 3 (mod 4)
           "0x3fffffffc00000004000000000000000"
           "00000000400000000000000000000000"_mp},
      }}},
    {"P-384",
     {48,
      128,
      crypto::HashAlgorithm::SHA384,
      {
          {"p",
           "0xffffffffffffffffffffffffffffffff"
           "fffffffffffffffffffffffffffffffe"
           "ffffffff0000000000000000ffffffff"_mp},
          {"a",
           "0xffffffffffffffffffffffffffffffff"
           "fffffffffffffffffffffffffffffffe"
           "ffffffff0000000000000000fffffffc"_mp},
          {"b",
           "0xb3312fa7e23ee7e4988e056be3f82d19"
           "181d9c6efe8141120314088f5013875a"
           "c656398d8a2ed19d2a85c8edd3ec2aef"_mp},
          {"z",
           "0xffffffffffffffffffffffffffffffff"
           "fffffffffffffffffffffffffffffffe"
           "ffffffff0000000000000000fffffff3"_mp},
          {"c1",  // RFC9390 I.1 sqrt for q = 3 (mod 4)
           "0x3fffffffffffffffffffffffffffffff"
           "ffffffffffffffffffffffffffffffffb"
           "fffffffc00000000000000040000000"_mp},
      }}},
    {"P-521",
     {66,
      128,
      crypto::HashAlgorithm::SHA512,
      {
          {"p",
           "0x01ffffffffffffffffffffffffffffff"
           "ffffffffffffffffffffffffffffffff"
           "ffffffffffffffffffffffffffffffff"
           "ffffffffffffffffffffffffffffffffffff"_mp},
          {"a",
           "0x01ffffffffffffffffffffffffffffff"
           "ffffffffffffffffffffffffffffffff"
           "ffffffffffffffffffffffffffffffff"
           "fffffffffffffffffffffffffffffffffffc"_mp},
          {"b",
           "0x0051953eb9618e1c9a1f929a21a0b685"
           "40eea2da725b99b315f3b8b489918ef1"
           "09e156193951ec7e937b1652c0bd3bb1"
           "bf073573df883d2c34f1ef451fd46b503f00"_mp},
          {"z",
           "0x01ffffffffffffffffffffffffffffff"
           "ffffffffffffffffffffffffffffffff"
           "ffffffffffffffffffffffffffffffff"
           "fffffffffffffffffffffffffffffffffffb"_mp},
          {"c1",  // RFC9390 I.1 sqrt for q = 3 (mod 4)
           "0x00800000000000000000000000000000"
           "00000000000000000000000000000000"
           "00000000000000000000000000000000"
           "000000000000000000000000000000000000"_mp},
      }}},
    {"Curve25519",
     {32,
      128,
      crypto::HashAlgorithm::SHA512,
      {
          {"p",
           "0x7fffffffffffffffffffffffffffffff"
           "ffffffffffffffffffffffffffffffed"_mp},
          {"a", "0x76d06"_mp},
          {"c2",  // RFC9380 I.2 sqrt for q = 5 (mod 8)
           "0x2b8324804fc1df0b2b4d00993dfbd7a7"
           "2f431806ad2fe478c4ee1b274a0ea0b1"_mp},
          {"sqrtm1",  // RFC9380 I.2 sqrt for q = 5 (mod 8)
           "0x547cdb7fb03e20f4d4b2ff66c2042858"
           "d0bce7f952d01b873b11e4d8b5f15f3d"_mp},
          {"c4",  // RFC9380 G.2.  Elligator 2 Method  map_to_curve_elligator2
           "0xffffffffffffffffffffffffffffffff"
           "ffffffffffffffffffffffffffffffd"_mp},
      }}}};

HashToCurveCtx GetHashToCurveCtxByName(const crypto::CurveName &name) {
  return kPredefinedCurveCtxs[name];
}

yacl::math::MPInt DeserializeMPInt(yacl::ByteContainerView buffer,
                                   const size_t key_size, yacl::Endian endian) {
  YACL_ENFORCE(buffer.size() == key_size);
  yacl::math::MPInt mp;

  mp.FromMagBytes(buffer, endian);

  return mp;
}

void MPIntToBytesWithPad(std::vector<uint8_t> &buf, size_t key_size,
                         yacl::math::MPInt &mp) {
  YACL_ENFORCE(buf.size() == key_size);
  yacl::Buffer mpbuf = mp.ToMagBytes(yacl::Endian::big);
  YACL_ENFORCE((size_t)(mpbuf.size()) <= buf.size(), "{},{}", mpbuf.size(),
               buf.size());

  std::memcpy(buf.data() + (key_size - mpbuf.size()), mpbuf.data(),
              mpbuf.size());
}

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

std::vector<uint8_t> ExpandMessageXmd(yacl::ByteContainerView msg,
                                      HashToCurveCtx &ctx,
                                      yacl::ByteContainerView dst,
                                      size_t len_in_bytes) {
  yacl::crypto::SslHash hash(ctx.hash_algo);
  size_t b_in_bytes = hash.DigestSize();
  size_t s_in_bytes = ctx.s_in_bytes;

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

  hash.Update(z_pad);
  hash.Update(msg);
  hash.Update(l_i_b_str);
  std::vector<uint8_t> z1(1);
  hash.Update(z1);
  hash.Update(dst_prime);

  std::vector<uint8_t> b_0 = hash.CumulativeHash();

  hash.Reset();
  // b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
  hash.Update(b_0);
  z1[0] = 1;
  hash.Update(z1);
  hash.Update(dst_prime);
  std::vector<uint8_t> b_1 = hash.CumulativeHash();
  hash.Reset();

  std::vector<uint8_t> ret;
  ret.insert(ret.end(), b_1.begin(), b_1.end());

  std::vector<uint8_t> b_i(b_0.size());
  std::memcpy(b_i.data(), b_1.data(), b_1.size());

  for (size_t i = 2; i <= ell; ++i) {
    for (size_t j = 0; j < b_i.size(); ++j) {
      b_i[j] = b_i[j] ^ b_0[j];
    }
    hash.Update(b_i);
    z1[0] = i;
    hash.Update(z1);
    hash.Update(dst_prime);
    b_i = hash.CumulativeHash();
    ret.insert(ret.end(), b_i.begin(), b_i.end());
    hash.Reset();
  }

  ret.resize(len_in_bytes);
  return ret;
}

std::vector<std::vector<uint8_t>> HashToField(yacl::ByteContainerView msg,
                                              size_t count, size_t l,
                                              HashToCurveCtx &ctx,
                                              const std::string &dst) {
  size_t len_in_bytes = count * l;

  std::vector<uint8_t> uniform_bytes =
      ExpandMessageXmd(msg, ctx, dst, len_in_bytes);

  std::vector<std::vector<uint8_t>> ret(count);

  for (size_t i = 0; i < count; ++i) {
    size_t elm_offset = l * i;
    absl::Span<uint8_t> data = absl::MakeSpan(&uniform_bytes[elm_offset], l);

    yacl::math::MPInt e_j;
    e_j.FromMagBytes(data, yacl::Endian::big);

    yacl::math::MPInt e_jp = e_j.Mod(ctx.aux["p"]);

    ret[i].resize(ctx.key_size);
    MPIntToBytesWithPad(ret[i], ctx.key_size, e_jp);
  }

  return ret;
}

yacl::math::MPInt HashToScalar(yacl::ByteContainerView msg,
                          size_t l,
                          HashToCurveCtx &ctx,
                          const std::string &dst) {
  std::vector<uint8_t> uniform_bytes =
      ExpandMessageXmd(msg, ctx, dst, l);

  absl::Span<uint8_t> data = absl::MakeSpan(&uniform_bytes[0], l);

  yacl::math::MPInt e_j;
  e_j.FromMagBytes(data, yacl::Endian::big);

  return e_j.Mod(ctx.aux["p"]);
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

bool Sgn0(const yacl::math::MPInt &v) {
  yacl::math::MPInt c;
  yacl::math::MPInt d;
  yacl::math::MPInt::Div(v, kMp2, &c, &d);

  bool ret = 1;
  if (d.IsZero()) {
    ret = 0;
  }

  return ret;
}

// RFC9380 I.1 sqrt for q = 3 (mod 4)
yacl::math::MPInt Sqrt3m4(const yacl::math::MPInt &x, HashToCurveCtx &ctx) {
  yacl::math::MPInt kMpC1 = ctx.aux["c1"];
  yacl::math::MPInt kMpp = ctx.aux["p"];

  // int c1 = 4;
  yacl::math::MPInt z;
  yacl::math::MPInt::PowMod(x, kMpC1, kMpp, &z);

  return z;
}

// RFC9380 I.2 sqrt for q = 5 (mod 8)
yacl::math::MPInt Sqrt5m8(const yacl::math::MPInt &v, HashToCurveCtx &ctx) {
  yacl::math::MPInt p = ctx.aux["p"];
  yacl::math::MPInt kMp3(3);
  yacl::math::MPInt kMp8(8);
  yacl::math::MPInt kMpSqrtm1 = ctx.aux["sqrtm1"];

  yacl::math::MPInt c2;
  yacl::math::MPInt::Add(p, kMp3, &c2);
  yacl::math::MPInt c;
  yacl::math::MPInt d;
  yacl::math::MPInt::Div(c2, kMp8, &c, &d);
  c2 = c;

  yacl::math::MPInt tv1 = v.PowMod(c2, p);
  yacl::math::MPInt tv2 = tv1.MulMod(kMpSqrtm1, p);

  c = tv1.MulMod(tv1, p);
  if (c == v) {
    return tv1;
  }
  return tv2;
}

std::pair<bool, yacl::math::MPInt> SqrtRatio(const yacl::math::MPInt &u,
                                             const yacl::math::MPInt &v,
                                             HashToCurveCtx &ctx) {
  yacl::math::MPInt kMpp = ctx.aux["p"];
  yacl::math::MPInt kMpZ = ctx.aux["z"];
  yacl::math::MPInt r;
  yacl::math::MPInt::InvertMod(v, kMpp, &r);

  r = r.MulMod(u, kMpp);

  bool b = IsSquare(r, kMpp);

  yacl::math::MPInt y;

  if (b) {
    y = Sqrt3m4(r, ctx);
  } else {
    r = r.MulMod(kMpZ, kMpp);
    y = Sqrt3m4(r, ctx);
  }
  return std::make_pair(b, y);
}

std::pair<yacl::math::MPInt, yacl::math::MPInt> MapToCurveSSWU(
    yacl::ByteContainerView ubuf, HashToCurveCtx &ctx) {
  yacl::math::MPInt kMpp = ctx.aux["p"];
  yacl::math::MPInt kMpA = ctx.aux["a"];
  yacl::math::MPInt kMpB = ctx.aux["b"];
  yacl::math::MPInt kMpZ = ctx.aux["z"];
  YACL_ENFORCE(ubuf.size() > 0);

  yacl::math::MPInt u;
  u.FromMagBytes(ubuf, yacl::Endian::big);

  yacl::math::MPInt tv1;
  yacl::math::MPInt::MulMod(u, u, kMpp, &tv1);  // 1. tv1 = u^2

  tv1 = tv1.MulMod(kMpZ, kMpp);  // 2. tv1 = Z * tv1, where Z = -10

  yacl::math::MPInt tv2;
  yacl::math::MPInt::MulMod(tv1, tv1, kMpp, &tv2);  // 3. tv2 = tv1 ^ 2

  tv2 = tv2.AddMod(tv1, kMpp);  // 4. tv2 = tv2 + tv1

  yacl::math::MPInt tv3;
  yacl::math::MPInt::AddMod(tv2, kMp1, kMpp, &tv3);  // 5. tv3 = tv2 + 1

  tv3 = tv3.MulMod(kMpB, kMpp);  // 6. tv3 = B * tv3

  yacl::math::MPInt tv4;  // 7. tv4 = CMOV(Z, -tv2, tv2 != 0)
  if (!tv2.IsZero()) {
    yacl::math::MPInt::SubMod(kMpp, tv2, kMpp, &tv4);
  } else {
    tv4 = kMpZ;
  }

  tv4 = tv4.MulMod(kMpA, kMpp);  // 8. tv4 = A * tv4

  yacl::math::MPInt::MulMod(tv3, tv3, kMpp, &tv2);  // 9. tv2 = tv3^2

  yacl::math::MPInt tv6;
  yacl::math::MPInt::MulMod(tv4, tv4, kMpp, &tv6);  // 10. tv6 = tv4^2

  yacl::math::MPInt tv5;
  yacl::math::MPInt::MulMod(kMpA, tv6, kMpp, &tv5);  // 11. tv5 = A * tv6

  tv2 = tv2.AddMod(tv5, kMpp);  // 12. tv2 = tv2 + tv5
  tv2 = tv2.MulMod(tv3, kMpp);  // 13. tv2 = tv2 * tv3
  tv6 = tv6.MulMod(tv4, kMpp);  // 14. tv6 = tv6 * tv4

  yacl::math::MPInt::MulMod(kMpB, tv6, kMpp, &tv5);  // 15. tv5 = B * tv6

  tv2 = tv2.AddMod(tv5, kMpp);  // 16. tv2 = tv2 + tv5

  yacl::math::MPInt x;
  yacl::math::MPInt::MulMod(tv1, tv3, kMpp, &x);  // 17. x = tv1 * tv3

  bool is_gx1_square;
  yacl::math::MPInt y1;

  std::tie(is_gx1_square, y1) = SqrtRatio(
      tv2, tv6, ctx);  // 18. (is_gx1_square, y1) = sqrt_ratio(tv2, tv6)

  yacl::math::MPInt y;
  yacl::math::MPInt::MulMod(tv1, u, kMpp, &y);  // 19. y = tv1 * u

  y = y.MulMod(y1, kMpp);  // 20. y = y * y1

  if (is_gx1_square) {
    x = tv3;  // 21. x = CMOV(x, tv3, is_gx1_square)
    y = y1;   // 22. y = CMOV(y, y1, is_gx1_square)
  }

  bool e1 = (Sgn0(u) == Sgn0(y));  // 23. e1 = sgn0(u) == sgn0(y)

  if (!e1) {
    y = kMpp.SubMod(y, kMpp);
  }

  yacl::math::MPInt r;
  yacl::math::MPInt::InvertMod(tv4, kMpp, &r);
  yacl::math::MPInt::MulMod(x, r, kMpp, &x);  // 25. x = x / tv4

  // crypto::AffinePoint p(x, y);
  // return p;
  return std::make_pair(x, y);
}
}  // namespace yacl
