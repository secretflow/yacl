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
#include <vector>

#include "yacl/base/exception.h"
#include "yacl/crypto/hash/hash_interface.h"
#include "yacl/crypto/hash/ssl_hash.h"
#include "yacl/math/mpint/mp_int.h"

namespace yacl {

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
                                      const crypto::HashAlgorithm hash_algo,
                                      yacl::ByteContainerView dst,
                                      size_t len_in_bytes) {
  yacl::crypto::SslHash hash(hash_algo);
  size_t b_in_bytes = hash.DigestSize();
  size_t s_in_bytes;

  switch (hash_algo) {
    case crypto::HashAlgorithm::SHA256: {
      s_in_bytes = 64;
      break;
    }
    case crypto::HashAlgorithm::SHA384: {
      s_in_bytes = 128;
      break;
    }
    case crypto::HashAlgorithm::SHA512: {
      s_in_bytes = 128;
      break;
    }
    default: {
      YACL_THROW("unsupported hash algorithm");
    }
  }

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
                                              size_t key_size,
                                              crypto::HashAlgorithm hash_algo,
                                              yacl::math::MPInt p,
                                              const std::string &dst) {
  size_t len_in_bytes = count * l;

  std::vector<uint8_t> uniform_bytes =
      ExpandMessageXmd(msg, hash_algo, dst, len_in_bytes);

  std::vector<std::vector<uint8_t>> ret(count);

  for (size_t i = 0; i < count; ++i) {
    size_t elm_offset = l * i;
    absl::Span<uint8_t> data = absl::MakeSpan(&uniform_bytes[elm_offset], l);

    yacl::math::MPInt e_j;
    e_j.FromMagBytes(data, yacl::Endian::big);

    yacl::math::MPInt e_jp = e_j.Mod(p);

    ret[i].resize(key_size);
    MPIntToBytesWithPad(ret[i], key_size, e_jp);
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
}  // namespace yacl
