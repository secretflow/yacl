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

#include "yacl/math/bigint/gmp/gmp_int.h"

#include <spdlog/spdlog.h>

#include "yacl/base/exception.h"

using GMPWord = __uint128_t;

#define MP_SIZEOF_BITS(type) ((size_t)CHAR_BIT * sizeof(type))

#define GMP_MAX_COMBA                                               \
  (int)(1uL << (MP_SIZEOF_BITS(GMPWord) + MP_SIZEOF_BITS(uint8_t) - \
                (2u * (size_t)GMP_NUMB_BITS)))
#define GMP_WARRAY                                                   \
  (int)(1uL << ((MP_SIZEOF_BITS(GMPWord) + MP_SIZEOF_BITS(uint8_t) - \
                 (2u * (size_t)GMP_NUMB_BITS)) +                     \
                1u))

namespace yacl::math::gmp {

GMPInt::GMPInt() {
  YACL_ENFORCE(gmp_.IsLoaded(), "GMP is not loaded");
  gmp_.mpz_init_(z_);
}

GMPInt::GMPInt(const std::string& str, int base) {
  YACL_ENFORCE(gmp_.IsLoaded(), "GMP is not loaded");
  gmp_.mpz_init_set_str_(z_, str.data(), base);
}

GMPInt::GMPInt(const GMPInt& other) { gmp_.mpz_init_set_(z_, other.z_); }

GMPInt::GMPInt(GMPInt&& other) noexcept {
  gmp_.mpz_init_(z_);
  gmp_.mpz_swap_(other.z_, z_);
}

thread_local GMPInt::RandState GMPInt::rand_state_;

GMPInt& GMPInt::operator=(const GMPInt& other) {
  if (this != &other) {
    gmp_.mpz_set_(z_, other.z_);
  }
  return *this;
}

GMPInt& GMPInt::operator=(GMPInt&& other) noexcept {
  if (this != &other) {
    gmp_.mpz_swap_(other.z_, z_);
  }
  return *this;
}

GMPInt::~GMPInt() { gmp_.mpz_clear_(z_); }

void GMPInt::Set(const std::string& num, int radix) {
  gmp_.mpz_set_str_(z_, num.data(), radix);
}

void GMPInt::NegateInplace() { gmp_.mpz_neg_(z_, z_); }

GMPInt GMPInt::Pow(uint32_t e) const {
  GMPInt r;
  gmp_.mpz_pow_ui_(r.z_, z_, e);
  return r;
}

void GMPInt::PowInplace(uint32_t e) { gmp_.mpz_pow_ui_(z_, z_, e); }

bool GMPInt::IsNegative() const {
  // Refer to the `mpz_sgn` macro in gmp
  return z_->_mp_size < 0;
}

bool GMPInt::IsZero() const { return z_->_mp_size == 0; }

bool GMPInt::IsOdd() const {
  // Refer to the `mpz_odd_p` macro in gmp
  return (z_->_mp_size != 0) & (static_cast<int>(z_->_mp_d[0]));
}

bool GMPInt::IsPrime() const {
  // A composite number will be identified as a prime with an asymptotic
  // probability of less than 4^(-reps). Reasonable values of reps are between
  // 15 and 50.
  return gmp_.mpz_probab_prime_p_(z_, 40) > 0;
}

GMPInt& GMPInt::operator+=(const GMPInt& n) {
  gmp_.mpz_add_(z_, z_, n.z_);
  return *this;
}

GMPInt& GMPInt::operator-=(const GMPInt& n) {
  gmp_.mpz_sub_(z_, z_, n.z_);
  return *this;
}

GMPInt& GMPInt::operator*=(const GMPInt& n) {
  gmp_.mpz_mul_(z_, z_, n.z_);
  return *this;
}

GMPInt& GMPInt::operator/=(const GMPInt& n) {
  YACL_ENFORCE(!n.IsZero(), "Division by zero");
  gmp_.mpz_fdiv_q_(z_, z_, n.z_);
  return *this;
}

GMPInt& GMPInt::operator%=(const GMPInt& mod) {
  YACL_ENFORCE(!mod.IsZero(), "Division by zero");
  gmp_.mpz_fdiv_r_(z_, z_, mod.z_);
  return *this;
}

GMPInt& GMPInt::operator+=(uint64_t n) {
  gmp_.mpz_add_ui_(z_, z_, n);
  return *this;
}

GMPInt& GMPInt::operator-=(uint64_t n) {
  gmp_.mpz_sub_ui_(z_, z_, n);
  return *this;
}

GMPInt& GMPInt::operator*=(uint64_t n) {
  gmp_.mpz_mul_ui_(z_, z_, n);
  return *this;
}

GMPInt& GMPInt::operator/=(uint64_t n) {
  YACL_ENFORCE(n != 0, "Division by zero");
  gmp_.mpz_fdiv_q_ui_(z_, z_, n);
  return *this;
}

GMPInt& GMPInt::operator&=(const GMPInt& n) {
  gmp_.mpz_and_(z_, z_, n.z_);
  return *this;
}

GMPInt& GMPInt::operator|=(const GMPInt& n) {
  gmp_.mpz_ior_(z_, z_, n.z_);
  return *this;
}

GMPInt& GMPInt::operator^=(const GMPInt& n) {
  gmp_.mpz_xor_(z_, z_, n.z_);
  return *this;
}

GMPInt& GMPInt::operator<<=(mp_bitcnt_t bit_cnt) {
  gmp_.mpz_mul_2exp_(z_, z_, bit_cnt);
  return *this;
}

GMPInt GMPInt::operator<<(mp_bitcnt_t bit_cnt) const {
  GMPInt result;
  gmp_.mpz_mul_2exp_(result.z_, z_, bit_cnt);
  return result;
}

GMPInt& GMPInt::operator>>=(mp_bitcnt_t bit_cnt) {
  gmp_.mpz_tdiv_q_2exp_(z_, z_, bit_cnt);
  return *this;
}

GMPInt GMPInt::operator>>(mp_bitcnt_t bit_cnt) const {
  GMPInt result;
  gmp_.mpz_tdiv_q_2exp_(result.z_, z_, bit_cnt);
  return result;
}

GMPInt& GMPInt::operator++() {
  gmp_.mpz_add_ui_(z_, z_, 1);
  return *this;
}

GMPInt GMPInt::operator++(int) {
  GMPInt r = *this;
  gmp_.mpz_add_ui_(z_, z_, 1);
  return r;
}

GMPInt& GMPInt::operator--() {
  gmp_.mpz_sub_ui_(z_, z_, 1);
  return *this;
}

GMPInt GMPInt::operator--(int) {
  GMPInt r = *this;
  gmp_.mpz_sub_ui_(z_, z_, 1);
  return r;
}

GMPInt GMPInt::operator-() const {
  GMPInt r;
  gmp_.mpz_neg_(r.z_, z_);
  return r;
}

size_t GMPInt::BitCount() const {
  if (IsZero()) {
    return 0;
  }
  return gmp_.mpz_sizeinbase_(z_, 2);
}

GMPInt GMPInt::Abs() const {
  GMPInt r;
  gmp_.mpz_abs_(r.z_, z_);
  return r;
}

int GMPInt::CompareAbs(const GMPInt& other) const {
  return gmp_.mpz_cmpabs_(z_, other.z_);
}

int GMPInt::CompareAbs(int64_t other) const {
  return gmp_.mpz_cmpabs_ui_(z_, std::abs(other));
}

GMPInt GMPInt::AddMod(const GMPInt& other, const GMPInt& mod) const {
  return (*this + other) % mod;
}

GMPInt GMPInt::SubMod(const GMPInt& other, const GMPInt& mod) const {
  return (*this - other) % mod;
}

GMPInt GMPInt::MulMod(const GMPInt& other, const GMPInt& mod) const {
  return (*this * other) % mod;
}

GMPInt GMPInt::InvMod(const GMPInt& mod) const {
  GMPInt r;
  gmp_.mpz_invert_(r.z_, z_, mod.z_);
  return r;
}

GMPInt GMPInt::PowMod(const GMPInt& other, const GMPInt& mod) const {
  GMPInt r;
  gmp_.mpz_powm_(r.z_, z_, other.z_, mod.z_);
  return r;
}

GMPInt GMPInt::Lcm(const GMPInt& a, const GMPInt& b) {
  GMPInt r;
  GMPLoader::Instance().mpz_lcm_(r.z_, a.z_, b.z_);
  return r;
}

GMPInt GMPInt::Gcd(const GMPInt& a, const GMPInt& b) {
  GMPInt r;
  GMPLoader::Instance().mpz_gcd_(r.z_, a.z_, b.z_);
  return r;
}

GMPInt GMPInt::RandomExactBits(size_t bit_size) {
  YACL_ENFORCE(bit_size > 0, "bit_size must be positive");
  GMPInt r;
  GMPLoader::Instance().mpz_urandomb_(r.z_, rand_state_.Get(), bit_size);
  return r;
}

GMPInt GMPInt::RandomMonicExactBits(size_t bit_size) {
  YACL_ENFORCE(bit_size > 0, "bit_size must be positive");
  GMPInt r;
  do {
    GMPLoader::Instance().mpz_urandomb_(r.z_, rand_state_.Get(), bit_size);
  } while (r.BitCount() != bit_size);
  return r;
}

GMPInt GMPInt::RandomLtN(const GMPInt& n) {
  YACL_ENFORCE(!n.IsNegative() && !n.IsZero(), "n must be positive");
  GMPInt r;
  GMPLoader::Instance().mpz_urandomm_(r.z_, rand_state_.Get(), n.z_);
  return r;
}

GMPInt GMPInt::RandPrimeOver(mp_bitcnt_t bit_size, PrimeType prime_type) {
  YACL_ENFORCE(prime_type == PrimeType::Normal || prime_type == PrimeType::BBS,
               "Unsupported prime type {}", static_cast<int>(prime_type));
  GMPInt r;
  do {
    GMPLoader::Instance().mpz_urandomb_(r.z_, rand_state_.Get(), bit_size);
  } while (r.BitCount() != bit_size);

  GMPLoader::Instance().mpz_nextprime_(r.z_, r.z_);
  if (prime_type == PrimeType::BBS) {
    while (GMPLoader::Instance().mpz_fdiv_ui_(r.z_, 4) != 3) {
      GMPLoader::Instance().mpz_nextprime_(r.z_, r.z_);
    }
  }
  return r;
}

mp_limb_t GMPInt::MontgomerySetup(const GMPInt& mod) {
  mp_limb_t a = GMPLoader::Instance().mpz_getlimbn_(mod.z_, 0);
  YACL_ENFORCE((a & 1U) != 0);

  mp_limb_t x = (((a + 2U) & 4) << 1) + a;  // here x*a==1 mod 2**4
  x *= 2U - (a * x);                        // here x*a==1 mod 2**8
  x *= 2U - (a * x);                        // here x*a==1 mod 2**16
  x *= 2U - (a * x);                        // here x*a==1 mod 2**32
  x *= 2U - (a * x);                        // here x*a==1 mod 2**64

  // rho = -1/n mod b
  return ((static_cast<GMPWord>(1) << GMP_NUMB_BITS) - x) & GMP_NUMB_MASK;
}

GMPInt GMPInt::MontgomeryCalcNormalization(const GMPInt& mod) {
  GMPInt r(1);
  const auto& gmp = GMPLoader::Instance();
  size_t n_size = gmp.mpz_size_(mod.z_);
  int bits = gmp.mpz_sizeinbase_(mod.z_, 2) % GMP_NUMB_BITS;
  if (n_size > 1) {
    gmp.mpz_mul_2exp_(r.z_, r.z_, ((n_size - 1) * GMP_NUMB_BITS) + bits - 1);
  } else {
    gmp.mpz_set_ui_(r.z_, 1);
    bits = 1;
  }

  for (int i = bits - 1; i < GMP_NUMB_BITS; ++i) {
    gmp.mpz_mul_2exp_(r.z_, r.z_, 1);      // r <<= 1;
    if (gmp.mpz_cmp_(r.z_, mod.z_) > 0) {  // r > mod
      gmp.mpz_sub_(r.z_, r.z_, mod.z_);    // r -= mod;
    }
  }

  return r;
}

GMPInt& GMPInt::MontgomeryReduce(const GMPInt& mod, mp_limb_t rho) {
  const size_t n_size = gmp_.mpz_size_(mod.z_);
  const size_t x_size = gmp_.mpz_size_(z_);
  size_t limbs = n_size * 2 + 1;
#if 0  // NOLINT: MontgomeryReduceComba exhibits slower performance
  if (n_size < GMP_MAX_COMBA && x_size <= GMP_WARRAY && limbs < GMP_WARRAY) {
    return MontgomeryReduceComba(mod, rho);
  }
#endif
  const bool is_negative = z_->_mp_size < 0;
  const mp_limb_t* n = gmp_.mpz_limbs_read_(mod.z_);
  mp_limb_t* x = gmp_.mpz_limbs_modify_(z_, limbs);
  if (x_size < limbs) {
    memset(x + x_size, 0, sizeof(mp_limb_t) * (limbs - x_size));
  }

  // Main reduction loop
  for (size_t ix = 0; ix < n_size; ++ix) {
    // Multiply and add in place
    mp_limb_t mu = x[ix] * rho;  // & GMP_NUMB_MASK;
    mp_limb_t u = 0;             // carry
    size_t iy = 0;
    for (; iy + 3 < n_size; iy += 4) {
      GMPWord r1 = (static_cast<GMPWord>(mu) * n[iy]) + u + x[ix + iy];
      u = static_cast<mp_limb_t>(r1 >> GMP_NUMB_BITS);
      x[ix + iy] = r1 & GMP_NUMB_MASK;

      GMPWord r2 = (static_cast<GMPWord>(mu) * n[iy + 1]) + u + x[ix + iy + 1];
      u = static_cast<mp_limb_t>(r2 >> GMP_NUMB_BITS);
      x[ix + iy + 1] = r2 & GMP_NUMB_MASK;

      GMPWord r3 = (static_cast<GMPWord>(mu) * n[iy + 2]) + u + x[ix + iy + 2];
      u = static_cast<mp_limb_t>(r3 >> GMP_NUMB_BITS);
      x[ix + iy + 2] = r3 & GMP_NUMB_MASK;

      GMPWord r4 = (static_cast<GMPWord>(mu) * n[iy + 3]) + u + x[ix + iy + 3];
      u = static_cast<mp_limb_t>(r4 >> GMP_NUMB_BITS);
      x[ix + iy + 3] = r4 & GMP_NUMB_MASK;
    }

    for (; iy < n_size; ++iy) {
      GMPWord r = (static_cast<GMPWord>(mu) * n[iy]) + u + x[ix + iy];
      u = static_cast<mp_limb_t>(r >> GMP_NUMB_BITS);
      x[ix + iy] = r & GMP_NUMB_MASK;
    }

    // Propagate carries upwards as required
    size_t carry_idx = ix + iy;
    while (u != 0 && carry_idx < limbs) {
      GMPWord r = static_cast<GMPWord>(x[carry_idx]) + u;
      x[carry_idx] = r & GMP_NUMB_MASK;
      u = r >> GMP_NUMB_BITS;
      ++carry_idx;
    }
  }

  while (limbs > 0 && x[limbs - 1] == 0) {
    --limbs;
  }
  gmp_.mpz_limbs_finish_(z_, limbs);
  gmp_.mpz_tdiv_q_2exp_(z_, z_, n_size * GMP_NUMB_BITS);
  if (gmp_.mpz_cmp_(z_, mod.z_) >= 0) {
    gmp_.mpz_sub_(z_, z_, mod.z_);
  }
  z_->_mp_size = is_negative ? -z_->_mp_size : z_->_mp_size;

  return *this;
}

GMPInt& GMPInt::MontgomeryReduceComba(const GMPInt& mod, mp_limb_t rho) {
  static_assert(GMP_NUMB_BITS == MP_SIZEOF_BITS(mp_limb_t));
  const mp_limb_t* n = gmp_.mpz_limbs_read_(mod.z_);
  const size_t n_size = gmp_.mpz_size_(mod.z_);
  size_t x_size = gmp_.mpz_size_(z_);
  GMPWord w_arr[GMP_WARRAY];
  uint8_t carries[GMP_WARRAY];
  memset(carries, 0, sizeof(carries));

  mp_limb_t* x = gmp_.mpz_limbs_modify_(z_, n_size + 1);
  if (x_size < n_size + 1) {
    memset(x + x_size, 0, sizeof(mp_limb_t) * (n_size + 1 - x_size));
  }

  size_t ix = 0;
  for (; ix < x_size; ++ix) {
    w_arr[ix] = x[ix];
  }

  if (x_size < n_size * 2 + 1) {
    memset(w_arr + x_size, 0, sizeof(GMPWord) * (n_size * 2 + 1 - x_size));
  }

  auto PropagateCarry = [&w_arr, &carries](size_t ix) {
    if (__builtin_add_overflow(w_arr[ix + 1], w_arr[ix] >> GMP_NUMB_BITS,
                               &w_arr[ix + 1])) {
      ++carries[ix + 1];
    }
    if (__builtin_add_overflow(
            w_arr[ix + 1], static_cast<GMPWord>(carries[ix]) << GMP_NUMB_BITS,
            &w_arr[ix + 1])) {
      ++carries[ix + 1];
    }
  };

  for (ix = 0; ix < n_size; ++ix) {
    mp_limb_t mu = ((w_arr[ix] & GMP_NUMB_MASK) * rho) & GMP_NUMB_MASK;
    for (size_t iy = 0; iy < n_size; ++iy) {
      GMPWord tmp = static_cast<GMPWord>(mu) * static_cast<GMPWord>(n[iy]);
      if (__builtin_add_overflow(w_arr[ix + iy], tmp, &w_arr[ix + iy])) {
        ++carries[ix + iy];
      }
    }

    PropagateCarry(ix);
  }

  for (; ix < n_size * 2; ++ix) {
    PropagateCarry(ix);
  }

  for (ix = 0; ix < n_size + 1; ++ix) {
    x[ix] = w_arr[ix + n_size] & GMP_NUMB_MASK;
  }

  x_size = n_size + 1;
  while (x_size > 0 && x[x_size - 1] == 0) {
    --x_size;
  }

  gmp_.mpz_limbs_finish_(z_, x_size);

  if (gmp_.mpz_cmp_(z_, mod.z_) >= 0) {
    gmp_.mpz_sub_(z_, z_, mod.z_);
  }

  return *this;
}

uint8_t GMPInt::GetBit(size_t idx) const {
  if (IsNegative()) {
    mp_limb_t limb = gmp_.mpz_getlimbn_(z_, idx / GMP_NUMB_BITS);
    return (limb >> (idx % GMP_NUMB_BITS)) & 1;
  } else {
    return gmp_.mpz_tstbit_(z_, idx);
  }
}

void GMPInt::SetBit(size_t idx, uint8_t bit) {
  // Because GMP's clrbit and setbit functions behave as if two's complement
  // arithmetic is used, we convert the number to a non-negative value before
  // setting the bit
  if (z_->_mp_size < 0) {
    z_->_mp_size = -z_->_mp_size;

    if (bit == 0) {
      gmp_.mpz_clrbit_(z_, idx);
    } else {
      gmp_.mpz_setbit_(z_, idx);
    }

    z_->_mp_size = -z_->_mp_size;
  } else {
    if (bit == 0) {
      gmp_.mpz_clrbit_(z_, idx);
    } else {
      gmp_.mpz_setbit_(z_, idx);
    }
  }
}

// The serialize protocol:
// The value is stored in little-endian format, and the MSB of the last byte is
// the sign bit.
//
//      +--------+--------+--------+--------+
//      |DDDDDDDD|DDDDDDDD|DDDDDDDD|SDDDDDDD|
//      +--------+--------+--------+--------+
//                                  ▲
//                                  │
//                               sign bit
// D = data/payload; S = sign bit
size_t GMPInt::SerializeSize() const {
  return gmp_.mpz_sizeinbase_(z_, 2) / CHAR_BIT + 1;
}

yacl::Buffer GMPInt::Serialize() const {
  int64_t buf_len = SerializeSize();
  yacl::Buffer buf(buf_len);
  Serialize(buf.data<uint8_t>(), buf_len);
  return buf;
}

size_t GMPInt::Serialize(uint8_t* buf, size_t buf_len) const {
  size_t total_buf = SerializeSize();
  if (buf == nullptr) {
    return total_buf;
  }
  YACL_ENFORCE(buf_len >= total_buf,
               "buf is too small, min required={}, actual={}", total_buf,
               buf_len);

  // store num in Little-Endian
  buf[total_buf - 1] = 0;
  size_t count;
  gmp_.mpz_export_(buf, &count, -1, sizeof(uint8_t), -1, 0, z_);
  YACL_ENFORCE(total_buf == count || total_buf == count + 1,
               "bug: buf len mismatch, {} vs {}", total_buf, count);

  // write sign bit
  uint8_t sign = (z_->_mp_size < 0 ? 1 : 0) << 7;
  buf[total_buf - 1] |= sign;

  return total_buf;
}

void GMPInt::Deserialize(yacl::ByteContainerView buffer) {
  YACL_ENFORCE(!buffer.empty(), "GMPInt deserialize: empty buffer");
  gmp_.mpz_import_(z_, buffer.size(), -1, sizeof(uint8_t), -1, 0,
                   buffer.data());
  mp_bitcnt_t sgn_bit_idx = buffer.size() * CHAR_BIT - 1;
  if (gmp_.mpz_tstbit_(z_, sgn_bit_idx) != 0) {
    gmp_.mpz_clrbit_(z_, sgn_bit_idx);
    z_->_mp_size = -z_->_mp_size;  // must clear the bit first
  }
}

std::string GMPInt::ToString() const {
  char* str = gmp_.mpz_get_str_(nullptr, 10, z_);
  std::string ret(str);
  free(str);
  return ret;
}

std::string GMPInt::ToHexString() const {
  char* str = gmp_.mpz_get_str_(nullptr, 16, z_);
  std::string ret(str);
  free(str);
  return ret;
}

yacl::Buffer GMPInt::ToBytes(size_t byte_len, Endian endian) const {
  yacl::Buffer buf(byte_len);
  ToBytes(buf.data<unsigned char>(), byte_len, endian);
  return buf;
}

void GMPInt::ToBytes(unsigned char* buf, size_t buf_len, Endian endian) const {
  size_t byte_count = (gmp_.mpz_sizeinbase_(z_, 2) + 7) / 8;
  YACL_ENFORCE_GE(buf_len, byte_count, "Buffer is too small");
  memset(buf, 0, buf_len);
  int endianness = endian == Endian::big ? 1 : -1;
  if (endian == Endian::little) {
    gmp_.mpz_export_(buf, nullptr, endianness, 1, endianness, 0, z_);
  } else {
    gmp_.mpz_export_(buf + buf_len - byte_count, nullptr, endianness, 1,
                     endianness, 0, z_);
  }

  if (IsNegative()) {
    for (size_t i = 0; i < buf_len; ++i) {
      buf[i] = ~buf[i];
    }
    bool carry = true;
    if (endian == Endian::little) {
      for (size_t i = 0; i < buf_len && carry; ++i) {
        buf[i] = buf[i] + 1;
        carry = (buf[i] == 0);
      }
    } else {
      for (size_t i = buf_len; i > 0 && carry; --i) {
        buf[i - 1] = buf[i - 1] + 1;
        carry = (buf[i - 1] == 0);
      }
    }
  }
}

size_t GMPInt::ToMagBytes(unsigned char* buf, size_t buf_len,
                          Endian endian) const {
  size_t byte_count = (gmp_.mpz_sizeinbase_(z_, 2) + 7) / 8;
  if (buf == nullptr) {
    return byte_count;
  }

  YACL_ENFORCE_GE(buf_len, byte_count, "Buffer is too small");
  int endianness = endian == Endian::big ? 1 : -1;
  gmp_.mpz_export_(buf, &byte_count, endianness, 1, endianness, 0, z_);
  return byte_count;
}

void GMPInt::FromMagBytes(yacl::ByteContainerView buffer, Endian endian) {
  int endianness = endian == Endian::big ? 1 : -1;
  gmp_.mpz_import_(z_, buffer.size(), endianness, 1, endianness, 0,
                   buffer.data());
}

GMPInt operator+(const GMPInt& lhs, const GMPInt& rhs) {
  GMPInt result;
  GMPLoader::Instance().mpz_add_(result.z_, lhs.z_, rhs.z_);
  return result;
}

GMPInt operator-(const GMPInt& lhs, const GMPInt& rhs) {
  GMPInt result;
  GMPLoader::Instance().mpz_sub_(result.z_, lhs.z_, rhs.z_);
  return result;
}

GMPInt operator*(const GMPInt& lhs, const GMPInt& rhs) {
  GMPInt result;
  GMPLoader::Instance().mpz_mul_(result.z_, lhs.z_, rhs.z_);
  return result;
}

GMPInt operator/(const GMPInt& lhs, const GMPInt& rhs) {
  YACL_ENFORCE(!rhs.IsZero(), "Division by zero");
  GMPInt result;
  GMPLoader::Instance().mpz_fdiv_q_(result.z_, lhs.z_, rhs.z_);
  return result;
}

GMPInt operator%(const GMPInt& lhs, const GMPInt& rhs) {
  YACL_ENFORCE(!rhs.IsZero(), "Division by zero");
  GMPInt result;
  GMPLoader::Instance().mpz_fdiv_r_(result.z_, lhs.z_, rhs.z_);
  return result;
}

GMPInt operator+(const GMPInt& lhs, uint64_t rhs) {
  GMPInt result;
  GMPLoader::Instance().mpz_add_ui_(result.z_, lhs.z_, rhs);
  return result;
}

GMPInt operator-(const GMPInt& lhs, uint64_t rhs) {
  GMPInt result;
  GMPLoader::Instance().mpz_sub_ui_(result.z_, lhs.z_, rhs);
  return result;
}

GMPInt operator*(const GMPInt& lhs, uint64_t rhs) {
  GMPInt result;
  GMPLoader::Instance().mpz_mul_ui_(result.z_, lhs.z_, rhs);
  return result;
}

GMPInt operator/(const GMPInt& lhs, uint64_t rhs) {
  YACL_ENFORCE(rhs != 0, "Division by zero");
  GMPInt result;
  GMPLoader::Instance().mpz_fdiv_q_ui_(result.z_, lhs.z_, rhs);
  return result;
}

uint64_t operator%(const GMPInt& lhs, uint64_t rhs) {
  YACL_ENFORCE(rhs != 0, "Division by zero");
  return GMPLoader::Instance().mpz_fdiv_ui_(lhs.z_, rhs);
}

GMPInt operator&(const GMPInt& lhs, const GMPInt& rhs) {
  GMPInt result;
  GMPLoader::Instance().mpz_and_(result.z_, lhs.z_, rhs.z_);
  return result;
}

GMPInt operator|(const GMPInt& lhs, const GMPInt& rhs) {
  GMPInt result;
  GMPLoader::Instance().mpz_ior_(result.z_, lhs.z_, rhs.z_);
  return result;
}

GMPInt operator^(const GMPInt& lhs, const GMPInt& rhs) {
  GMPInt result;
  GMPLoader::Instance().mpz_xor_(result.z_, lhs.z_, rhs.z_);
  return result;
}

bool operator>(const GMPInt& lhs, const GMPInt& rhs) {
  return GMPLoader::Instance().mpz_cmp_(lhs.z_, rhs.z_) > 0;
}

bool operator<(const GMPInt& lhs, const GMPInt& rhs) {
  return GMPLoader::Instance().mpz_cmp_(lhs.z_, rhs.z_) < 0;
}

bool operator>=(const GMPInt& lhs, const GMPInt& rhs) {
  return GMPLoader::Instance().mpz_cmp_(lhs.z_, rhs.z_) >= 0;
}

bool operator<=(const GMPInt& lhs, const GMPInt& rhs) {
  return GMPLoader::Instance().mpz_cmp_(lhs.z_, rhs.z_) <= 0;
}

bool operator==(const GMPInt& lhs, const GMPInt& rhs) {
  return GMPLoader::Instance().mpz_cmp_(lhs.z_, rhs.z_) == 0;
}

bool operator!=(const GMPInt& lhs, const GMPInt& rhs) {
  return GMPLoader::Instance().mpz_cmp_(lhs.z_, rhs.z_) != 0;
}

bool operator>(const GMPInt& lhs, int64_t rhs) {
  return GMPLoader::Instance().mpz_cmp_si_(lhs.z_, rhs) > 0;
}

bool operator<(const GMPInt& lhs, int64_t rhs) {
  return GMPLoader::Instance().mpz_cmp_si_(lhs.z_, rhs) < 0;
}

bool operator>=(const GMPInt& lhs, int64_t rhs) {
  return GMPLoader::Instance().mpz_cmp_si_(lhs.z_, rhs) >= 0;
}

bool operator<=(const GMPInt& lhs, int64_t rhs) {
  return GMPLoader::Instance().mpz_cmp_si_(lhs.z_, rhs) <= 0;
}

bool operator==(const GMPInt& lhs, int64_t rhs) {
  return GMPLoader::Instance().mpz_cmp_si_(lhs.z_, rhs) == 0;
}

bool operator!=(const GMPInt& lhs, int64_t rhs) {
  return GMPLoader::Instance().mpz_cmp_si_(lhs.z_, rhs) != 0;
}

}  // namespace yacl::math::gmp
