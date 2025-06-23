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

#include "yacl/math/bigint/openssl/bignum.h"

#include <openssl/bio.h>
#include <openssl/err.h>

#include "absl/strings/str_format.h"

#include "yacl/base/exception.h"

// ---------------------------------
// Helpers for OpenSSL return values
// ---------------------------------
/* enforce return code == 1 */
#define OSSL_RET_1(MP_ERR) YACL_ENFORCE_EQ((MP_ERR), 1, GetOSSLErr())

#define OSSL_RET_NOT_0(MP_ERR) YACL_ENFORCE_NE((MP_ERR), 0, GetOSSLErr())

/* enforce return value != -1 */
#define OSSL_RET_NOT_MINUS_1(MP_ERR) YACL_ENFORCE_NE((MP_ERR), -1, GetOSSLErr())

/* enforce return value != nullptr */
#define OSSL_RET_NOT_NULL(MP_ERR) \
  YACL_ENFORCE((MP_ERR) != nullptr, GetOSSLErr())

namespace yacl::math::openssl {

namespace {

// see: https://en.wikibooks.org/wiki/OpenSSL/Error_handling
std::string GetOSSLErr() {
  BIO* bio = BIO_new(BIO_s_mem());
  ERR_print_errors(bio);
  char* buf;
  size_t len = BIO_get_mem_data(bio, &buf);
  std::string ret(buf, len);
  BIO_free(bio);
  return ret;
}

UniqueBnCtxPtr InitBnCtx() {
  auto bn_ctx = UniqueBnCtxPtr(BN_CTX_new(), BN_CTX_free);
  OSSL_RET_NOT_NULL(bn_ctx);
  return bn_ctx;
}

}  // namespace

thread_local UniqueBnCtxPtr BigNum::bn_ctx_ = InitBnCtx();

BigNum::BigNum() {
  bn_ = {BN_new(), BN_free};
  OSSL_RET_NOT_NULL(bn_);
}

BigNum::BigNum(const std::string& str, int base) {
  // TODO: Support non-positive base
  YACL_ENFORCE(base > 0, "Base must be positive");
  BIGNUM* bn = nullptr;
  switch (base) {
    case 10:
      OSSL_RET_NOT_0(BN_dec2bn(&bn, str.data()));
      break;
    case 16:
      OSSL_RET_NOT_0(BN_hex2bn(&bn, str.data()));
      break;
    default:
      YACL_ENFORCE(false, "Unsupported base: {}", base);
  }
  bn_ = {bn, BN_free};
}

BigNum::BigNum(const BigNum& other) {
  bn_ = {BN_dup(other.bn_.get()), BN_free};
  OSSL_RET_NOT_NULL(bn_);
}

BigNum::BigNum(BigNum&& other) noexcept { std::swap(bn_, other.bn_); }

BigNum& BigNum::operator=(const BigNum& other) {
  if (this != &other) {
    BN_copy(bn_.get(), other.bn_.get());
    OSSL_RET_NOT_NULL(bn_);
  }
  return *this;
}

BigNum& BigNum::operator=(BigNum&& other) noexcept {
  if (this != &other) {
    std::swap(bn_, other.bn_);
  }
  return *this;
}

void BigNum::Set(const std::string& num, int radix) {
  *this = BigNum(num, radix);
}

BigNum& BigNum::operator+=(const BigNum& other) {
  OSSL_RET_1(BN_add(bn_.get(), bn_.get(), other.bn_.get()));
  return *this;
}

BigNum& BigNum::operator-=(const BigNum& other) {
  OSSL_RET_1(BN_sub(bn_.get(), bn_.get(), other.bn_.get()));
  return *this;
}

BigNum& BigNum::operator*=(const BigNum& other) {
  OSSL_RET_1(
      BN_mul(bn_.get(), bn_.get(), other.bn_.get(), BigNum::bn_ctx_.get()));
  return *this;
}

BigNum& BigNum::operator/=(const BigNum& other) {
  YACL_ENFORCE(!other.IsZero(), "Division by zero");
  BigNum remainder;
  OSSL_RET_1(BN_div(bn_.get(), remainder.bn_.get(), bn_.get(), other.bn_.get(),
                    BigNum::bn_ctx_.get()));
  if (this->IsNegative() && !remainder.IsZero()) {
    --(*this);  // Rounds quotient down towards −infinity
  }
  return *this;
}

BigNum& BigNum::operator%=(const BigNum& mod) {
  if (mod.IsNegative()) {
    OSSL_RET_1(
        BN_mod(bn_.get(), bn_.get(), mod.bn_.get(), BigNum::bn_ctx_.get()));
    if (!this->IsNegative() && !this->IsZero()) {
      this->operator+=(mod);  // Rounds quotient down towards −infinity
    }
  } else {
    OSSL_RET_1(
        BN_nnmod(bn_.get(), bn_.get(), mod.bn_.get(), BigNum::bn_ctx_.get()));
  }
  return *this;
}

BigNum& BigNum::operator+=(uint64_t value) {
  OSSL_RET_1(BN_add_word(bn_.get(), value));
  return *this;
}

BigNum& BigNum::operator-=(uint64_t value) {
  OSSL_RET_1(BN_sub_word(bn_.get(), value));
  return *this;
}

BigNum& BigNum::operator*=(uint64_t value) {
  OSSL_RET_1(BN_mul_word(bn_.get(), value));
  return *this;
}

BigNum& BigNum::operator/=(uint64_t value) {
  YACL_ENFORCE(value != 0, "Division by zero");
  uint64_t remainder = BN_div_word(bn_.get(), value);
  if (this->IsNegative() && remainder != 0) {
    --(*this);  // Rounds quotient down towards −infinity
  }
  return *this;
}

BigNum& BigNum::operator&=(const BigNum& other) {
  *this = *this & other;
  return *this;
}

BigNum& BigNum::operator|=(const BigNum& other) {
  *this = *this | other;
  return *this;
}

BigNum& BigNum::operator^=(const BigNum& other) {
  *this = *this ^ other;
  return *this;
}

BigNum& BigNum::operator<<=(size_t shift) {
  YACL_ENFORCE(shift <= std::numeric_limits<int>::max(),
               "Shift value too large: {}", shift);
  OSSL_RET_1(BN_lshift(bn_.get(), bn_.get(), shift));
  return *this;
}

BigNum& BigNum::operator>>=(size_t shift) {
  YACL_ENFORCE(shift <= std::numeric_limits<int>::max(),
               "Shift value too large: {}", shift);
  OSSL_RET_1(BN_rshift(bn_.get(), bn_.get(), shift));
  return *this;
}

BigNum& BigNum::operator++() {
  OSSL_RET_1(BN_add_word(bn_.get(), 1));
  return *this;
}

BigNum BigNum::operator++(int) {
  BigNum r = *this;
  OSSL_RET_1(BN_add_word(bn_.get(), 1));
  return r;
}

BigNum& BigNum::operator--() {
  OSSL_RET_1(BN_sub_word(bn_.get(), 1));
  return *this;
}

BigNum BigNum::operator--(int) {
  BigNum r = *this;
  OSSL_RET_1(BN_sub_word(bn_.get(), 1));
  return r;
}

BigNum BigNum::operator-() const {
  BigNum r = *this;
  r.NegateInplace();
  return r;
}

void BigNum::NegateInplace() {
  BN_set_negative(bn_.get(), static_cast<int>(BN_is_negative(bn_.get()) != 1));
}

BigNum BigNum::Pow(uint32_t e) const {
  BigNum r;
  OSSL_RET_1(BN_exp(r.bn_.get(), bn_.get(), BigNum(e).bn_.get(),
                    BigNum::bn_ctx_.get()));
  return r;
}

void BigNum::PowInplace(uint32_t e) {
  OSSL_RET_1(
      BN_exp(bn_.get(), bn_.get(), BigNum(e).bn_.get(), BigNum::bn_ctx_.get()));
}

bool BigNum::IsNegative() const { return BN_is_negative(bn_.get()) == 1; }

bool BigNum::IsZero() const { return BN_is_zero(bn_.get()) == 1; }

bool BigNum::IsOdd() const { return BN_is_odd(bn_.get()) == 1; }

bool BigNum::IsPrime() const {
  return BN_check_prime(bn_.get(), BigNum::bn_ctx_.get(), nullptr) == 1;
}

size_t BigNum::BitCount() const { return BN_num_bits(bn_.get()); }

BigNum BigNum::Abs() const {
  BigNum r = *this;
  BN_set_negative(r.bn_.get(), 0);
  return r;
}

int BigNum::CompareAbs(const BigNum& other) const {
  return BN_ucmp(bn_.get(), other.bn_.get());
}

int BigNum::CompareAbs(int64_t other) const {
  return CompareAbs(BigNum(other));
}

BigNum BigNum::AddMod(const BigNum& other, const BigNum& mod) const {
  BigNum r;
  OSSL_RET_1(BN_mod_add(r.bn_.get(), bn_.get(), other.bn_.get(), mod.bn_.get(),
                        BigNum::bn_ctx_.get()));
  return r;
}

BigNum BigNum::SubMod(const BigNum& other, const BigNum& mod) const {
  BigNum r;
  OSSL_RET_1(BN_mod_sub(r.bn_.get(), bn_.get(), other.bn_.get(), mod.bn_.get(),
                        BigNum::bn_ctx_.get()));
  return r;
}

BigNum BigNum::MulMod(const BigNum& other, const BigNum& mod) const {
  BigNum r;
  OSSL_RET_1(BN_mod_mul(r.bn_.get(), bn_.get(), other.bn_.get(), mod.bn_.get(),
                        BigNum::bn_ctx_.get()));
  return r;
}

BigNum BigNum::InvMod(const BigNum& mod) const {
  BigNum r;
  OSSL_RET_NOT_NULL(BN_mod_inverse(r.bn_.get(), bn_.get(), mod.bn_.get(),
                                   BigNum::bn_ctx_.get()));
  return r;
}

BigNum BigNum::PowMod(const BigNum& other, const BigNum& mod) const {
  // When mod is even, computational efficiency tends to degrade significantly
  BigNum r;
  if (other.IsNegative()) {
    BigNum inv = InvMod(mod);
    OSSL_RET_1(BN_mod_exp(r.bn_.get(), inv.bn_.get(), other.Abs().bn_.get(),
                          mod.bn_.get(), BigNum::bn_ctx_.get()));
  } else {
    OSSL_RET_1(BN_mod_exp(r.bn_.get(), bn_.get(), other.bn_.get(),
                          mod.bn_.get(), BigNum::bn_ctx_.get()));
  }
  return r;
}

BigNum BigNum::Lcm(const BigNum& a, const BigNum& b) {
  auto r = a * b / Gcd(a, b);
  if (r.IsNegative()) {
    r.NegateInplace();
  }
  return r;
}

BigNum BigNum::Gcd(const BigNum& a, const BigNum& b) {
  BigNum r;
  OSSL_RET_1(
      BN_gcd(r.bn_.get(), a.bn_.get(), b.bn_.get(), BigNum::bn_ctx_.get()));
  return r;
}

BigNum BigNum::RandomExactBits(size_t bit_size) {
  YACL_ENFORCE(bit_size > 0, "bit_size must be positive");
  BigNum r;
  OSSL_RET_1(BN_rand_ex(r.bn_.get(), bit_size, BN_RAND_TOP_ANY,
                        BN_RAND_BOTTOM_ANY, 0, BigNum::bn_ctx_.get()));
  return r;
}

BigNum BigNum::RandomMonicExactBits(size_t bit_size) {
  YACL_ENFORCE(bit_size > 0, "bit_size must be positive");
  BigNum r;
  OSSL_RET_1(BN_rand_ex(r.bn_.get(), bit_size, BN_RAND_TOP_ONE,
                        BN_RAND_BOTTOM_ANY, 0, BigNum::bn_ctx_.get()));
  return r;
}

BigNum BigNum::RandomLtN(const BigNum& n) {
  YACL_ENFORCE(n > 0, "n must be positive");
  BigNum r;
  OSSL_RET_1(
      BN_rand_range_ex(r.bn_.get(), n.bn_.get(), 0, BigNum::bn_ctx_.get()));
  return r;
}

BigNum BigNum::RandPrimeOver(size_t bit_size, PrimeType prime_type) {
  BigNum r;
  int safe = static_cast<int>(prime_type == PrimeType::Safe ||
                              prime_type == PrimeType::FastSafe);

  if (prime_type == PrimeType::BBS) {
    OSSL_RET_1(BN_generate_prime_ex2(r.bn_.get(), bit_size, safe,
                                     BigNum(4).bn_.get(), BigNum(3).bn_.get(),
                                     nullptr, BigNum::bn_ctx_.get()));
  } else {
    OSSL_RET_1(BN_generate_prime_ex2(r.bn_.get(), bit_size, safe, nullptr,
                                     nullptr, nullptr, BigNum::bn_ctx_.get()));
  }

  return r;
}

UniqueBnMontCtxPtr BigNum::SetMontgomeryCtx(const BigNum& mod) {
  auto bn_mont_ctx = UniqueBnMontCtxPtr(BN_MONT_CTX_new(), BN_MONT_CTX_free);
  OSSL_RET_NOT_NULL(bn_mont_ctx);
  OSSL_RET_1(
      BN_MONT_CTX_set(bn_mont_ctx.get(), mod.bn_.get(), BigNum::bn_ctx_.get()));
  return bn_mont_ctx;
}

BigNum& BigNum::ToMontgomery(const UniqueBnMontCtxPtr& mont_ctx) {
  OSSL_RET_1(BN_to_montgomery(bn_.get(), bn_.get(), mont_ctx.get(),
                              BigNum::bn_ctx_.get()));
  return *this;
}

BigNum& BigNum::FromMontgomery(const UniqueBnMontCtxPtr& mont_ctx) {
  OSSL_RET_1(BN_from_montgomery(bn_.get(), bn_.get(), mont_ctx.get(),
                                BigNum::bn_ctx_.get()));
  return *this;
}

BigNum BigNum::MulModMontgomery(const BigNum& a, const BigNum& b,
                                const UniqueBnMontCtxPtr& mont_ctx) {
  BigNum r;
  OSSL_RET_1(BN_mod_mul_montgomery(r.bn_.get(), a.bn_.get(), b.bn_.get(),
                                   mont_ctx.get(), BigNum::bn_ctx_.get()));
  return r;
}

BigNum BigNum::PowModMontgomery(const BigNum& a, const BigNum& b,
                                const BigNum& mod,
                                const UniqueBnMontCtxPtr& mont_ctx) {
  BigNum r;
  OSSL_RET_1(BN_mod_exp_mont(r.bn_.get(), a.bn_.get(), b.bn_.get(),
                             mod.bn_.get(), BigNum::bn_ctx_.get(),
                             mont_ctx.get()));
  return r;
}

uint8_t BigNum::GetBit(size_t idx) const {
  return BN_is_bit_set(bn_.get(), idx);
}

void BigNum::SetBit(size_t idx, uint8_t bit) {
  if (bit == 0U) {
    if (idx < BitCount()) {
      OSSL_RET_1(BN_clear_bit(bn_.get(), idx));
    }
  } else {
    OSSL_RET_1(BN_set_bit(bn_.get(), idx));
  }
}

// The serialize protocol:
// The value is stored in little-endian format, and the MSB of the last byte
// is the sign bit.
//
//      +--------+--------+--------+--------+
//      |DDDDDDDD|DDDDDDDD|DDDDDDDD|SDDDDDDD|
//      +--------+--------+--------+--------+
//                                  ▲
//                                  │
//                               sign bit
// D = data/payload; S = sign bit
size_t BigNum::SerializeSize() const {
  return BN_num_bits(bn_.get()) / CHAR_BIT + 1;
}

yacl::Buffer BigNum::Serialize() const {
  int64_t buf_len = SerializeSize();
  yacl::Buffer buf(buf_len);
  Serialize(buf.data<uint8_t>(), buf_len);
  return buf;
}

size_t BigNum::Serialize(uint8_t* buf, size_t buf_len) const {
  size_t total_buf = SerializeSize();
  if (buf == nullptr) {
    return total_buf;
  }
  YACL_ENFORCE(buf_len >= total_buf,
               "buf is too small, min required={}, actual={}", total_buf,
               buf_len);

  // Store num in Little-Endian
  OSSL_RET_NOT_MINUS_1(BN_bn2lebinpad(bn_.get(), buf, buf_len));

  // Write sign bit
  uint8_t sign = BN_is_negative(bn_.get()) << 7;
  buf[total_buf - 1] |= sign;

  return total_buf;
}

void BigNum::Deserialize(yacl::ByteContainerView buffer) {
  YACL_ENFORCE(!buffer.empty(), "BigNum deserialize: empty buffer");
  OSSL_RET_NOT_NULL(BN_lebin2bn(buffer.data(), buffer.size(), bn_.get()));
  int sgn_bit_idx = buffer.size() * CHAR_BIT - 1;
  if (BN_is_bit_set(bn_.get(), sgn_bit_idx) == 1) {
    OSSL_RET_1(BN_clear_bit(bn_.get(), sgn_bit_idx));
    BN_set_negative(bn_.get(), 1);
  }
}

std::string BigNum::ToString() const {
  char* bin_str = BN_bn2dec(bn_.get());
  OSSL_RET_NOT_NULL(bin_str);
  std::string ret(bin_str);
  OPENSSL_free(bin_str);
  return ret;
}

std::string BigNum::ToHexString() const {
  char* hex_str = BN_bn2hex(bn_.get());
  OSSL_RET_NOT_NULL(hex_str);
  std::string ret(hex_str);
  OPENSSL_free(hex_str);
  return ret;
}

yacl::Buffer BigNum::ToBytes(size_t byte_len, Endian endian) const {
  yacl::Buffer buf(byte_len);
  ToBytes(buf.data<unsigned char>(), byte_len, endian);
  return buf;
}

void BigNum::ToBytes(unsigned char* buf, size_t buf_len, Endian endian) const {
  size_t byte_count = BN_num_bytes(bn_.get());
  if (buf_len < byte_count) {
    std::vector<unsigned char> tmp(byte_count);
    ToBytes(tmp.data(), byte_count, endian);
    if (endian == Endian::little) {
      memcpy(buf, tmp.data(), buf_len);
    } else {
      memcpy(buf, tmp.data() + byte_count - buf_len, buf_len);
    }
    return;
  }
  memset(buf, 0, buf_len);
  if (endian == Endian::big) {
    OSSL_RET_NOT_MINUS_1(BN_bn2binpad(bn_.get(), buf, buf_len));
  } else if (endian == Endian::little) {
    OSSL_RET_NOT_MINUS_1(BN_bn2lebinpad(bn_.get(), buf, buf_len));
  } else {
    OSSL_RET_NOT_MINUS_1(BN_bn2nativepad(bn_.get(), buf, buf_len));
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

size_t BigNum::ToMagBytes(unsigned char* buf, size_t buf_len,
                          Endian endian) const {
  size_t num_bytes = BN_num_bytes(bn_.get());
  if (buf == nullptr) {
    return num_bytes;
  }

  YACL_ENFORCE_GE(buf_len, num_bytes, "Buffer is too small");
  if (endian == Endian::big) {
    return BN_bn2bin(bn_.get(), buf);
  } else if (endian == Endian::little) {
    return BN_bn2lebinpad(bn_.get(), buf, num_bytes);
  } else {
    return BN_bn2nativepad(bn_.get(), buf, num_bytes);
  }
}

void BigNum::FromMagBytes(yacl::ByteContainerView buffer, Endian endian) {
  if (endian == Endian::big) {
    OSSL_RET_NOT_NULL(BN_bin2bn(buffer.data(), buffer.size(), bn_.get()));
  } else if (endian == Endian::little) {
    OSSL_RET_NOT_NULL(BN_lebin2bn(buffer.data(), buffer.size(), bn_.get()));
  } else {
    OSSL_RET_NOT_NULL(BN_native2bn(buffer.data(), buffer.size(), bn_.get()));
  }
}

BigNum operator+(const BigNum& lhs, const BigNum& rhs) {
  BigNum result;
  OSSL_RET_1(BN_add(result.bn_.get(), lhs.bn_.get(), rhs.bn_.get()));
  return result;
}

BigNum operator-(const BigNum& lhs, const BigNum& rhs) {
  BigNum result;
  OSSL_RET_1(BN_sub(result.bn_.get(), lhs.bn_.get(), rhs.bn_.get()));
  return result;
}

BigNum operator*(const BigNum& lhs, const BigNum& rhs) {
  BigNum result;
  OSSL_RET_1(BN_mul(result.bn_.get(), lhs.bn_.get(), rhs.bn_.get(),
                    BigNum::bn_ctx_.get()));
  return result;
}

BigNum operator/(const BigNum& lhs, const BigNum& rhs) {
  YACL_ENFORCE(!rhs.IsZero(), "Division by zero");
  BigNum result;
  BigNum remainder;
  OSSL_RET_1(BN_div(result.bn_.get(), remainder.bn_.get(), lhs.bn_.get(),
                    rhs.bn_.get(), BigNum::bn_ctx_.get()));
  if (result.IsNegative() && !remainder.IsZero()) {
    --result;  // Rounds quotient down towards −infinity
  }

  return result;
}

BigNum operator%(const BigNum& lhs, const BigNum& rhs) {
  YACL_ENFORCE(!rhs.IsZero(), "Division by zero");
  BigNum result;
  if (rhs.IsNegative()) {
    OSSL_RET_1(BN_mod(result.bn_.get(), lhs.bn_.get(), rhs.bn_.get(),
                      BigNum::bn_ctx_.get()));
    if (!result.IsNegative() && !result.IsZero()) {
      result += rhs;  // Rounds quotient down towards −infinity
    }
  } else {
    OSSL_RET_1(BN_nnmod(result.bn_.get(), lhs.bn_.get(), rhs.bn_.get(),
                        BigNum::bn_ctx_.get()));
  }
  return result;
}

BigNum operator+(const BigNum& lhs, uint64_t rhs) {
  BigNum result = lhs;
  OSSL_RET_1(BN_add_word(result.bn_.get(), rhs));
  return result;
}

BigNum operator-(const BigNum& lhs, uint64_t rhs) {
  BigNum result = lhs;
  OSSL_RET_1(BN_sub_word(result.bn_.get(), rhs));
  return result;
}

BigNum operator*(const BigNum& lhs, uint64_t rhs) {
  BigNum result = lhs;
  OSSL_RET_1(BN_mul_word(result.bn_.get(), rhs));
  return result;
}

BigNum operator/(const BigNum& lhs, uint64_t rhs) {
  YACL_ENFORCE(rhs != 0, "Division by zero");
  BigNum result = lhs;
  uint64_t remainder = BN_div_word(result.bn_.get(), rhs);
  if (result.IsNegative() && remainder != 0) {
    --result;  // Rounds quotient down towards −infinity
  }
  return result;
}

uint64_t operator%(const BigNum& lhs, uint64_t rhs) {
  YACL_ENFORCE(rhs > 0, "modulus must be positive");
  uint64_t result = BN_mod_word(lhs.bn_.get(), rhs);
  if (lhs.IsNegative() && result != 0) {
    result = rhs - result;
  }
  return result;
}

BigNum operator&(const BigNum& lhs, const BigNum& rhs) {
  size_t max_bits = std::max(lhs.BitCount(), rhs.BitCount());
  // Add one more byte for sign bit padding
  size_t num_bytes = (max_bits + 7) / 8 + 1;
  std::vector<unsigned char> lhs_buf(num_bytes, 0);
  std::vector<unsigned char> rhs_buf(num_bytes, 0);
  lhs.ToBytes(lhs_buf.data(), num_bytes, Endian::little);
  rhs.ToBytes(rhs_buf.data(), num_bytes, Endian::little);
  for (size_t i = 0; i < num_bytes; ++i) {
    lhs_buf[i] &= rhs_buf[i];
  }

  BigNum result;
  BN_signed_lebin2bn(lhs_buf.data(), num_bytes, result.bn_.get());
  return result;
}

BigNum operator|(const BigNum& lhs, const BigNum& rhs) {
  size_t max_bits = std::max(lhs.BitCount(), rhs.BitCount());
  // Add one more byte for sign bit padding
  size_t num_bytes = (max_bits + 7) / 8 + 1;
  std::vector<unsigned char> lhs_buf(num_bytes, 0);
  std::vector<unsigned char> rhs_buf(num_bytes, 0);
  lhs.ToBytes(lhs_buf.data(), num_bytes, Endian::little);
  rhs.ToBytes(rhs_buf.data(), num_bytes, Endian::little);
  for (size_t i = 0; i < num_bytes; ++i) {
    lhs_buf[i] |= rhs_buf[i];
  }

  BigNum result;
  BN_signed_lebin2bn(lhs_buf.data(), num_bytes, result.bn_.get());
  return result;
}

BigNum operator^(const BigNum& lhs, const BigNum& rhs) {
  size_t max_bits = std::max(lhs.BitCount(), rhs.BitCount());
  // Add one more byte for sign bit padding
  size_t num_bytes = (max_bits + 7) / 8 + 1;
  std::vector<unsigned char> lhs_buf(num_bytes, 0);
  std::vector<unsigned char> rhs_buf(num_bytes, 0);
  lhs.ToBytes(lhs_buf.data(), num_bytes, Endian::little);
  rhs.ToBytes(rhs_buf.data(), num_bytes, Endian::little);
  for (size_t i = 0; i < num_bytes; ++i) {
    lhs_buf[i] ^= rhs_buf[i];
  }

  BigNum result;
  BN_signed_lebin2bn(lhs_buf.data(), num_bytes, result.bn_.get());
  return result;
}

bool operator>(const BigNum& lhs, const BigNum& rhs) {
  return BN_cmp(lhs.bn_.get(), rhs.bn_.get()) > 0;
}

bool operator<(const BigNum& lhs, const BigNum& rhs) {
  return BN_cmp(lhs.bn_.get(), rhs.bn_.get()) < 0;
}

bool operator>=(const BigNum& lhs, const BigNum& rhs) {
  return BN_cmp(lhs.bn_.get(), rhs.bn_.get()) >= 0;
}

bool operator<=(const BigNum& lhs, const BigNum& rhs) {
  return BN_cmp(lhs.bn_.get(), rhs.bn_.get()) <= 0;
}

bool operator==(const BigNum& lhs, const BigNum& rhs) {
  return BN_cmp(lhs.bn_.get(), rhs.bn_.get()) == 0;
}

bool operator!=(const BigNum& lhs, const BigNum& rhs) {
  return BN_cmp(lhs.bn_.get(), rhs.bn_.get()) != 0;
}

bool operator>(const BigNum& lhs, int64_t rhs) {
  return BN_cmp(lhs.bn_.get(), BigNum(rhs).bn_.get()) > 0;
}

bool operator<(const BigNum& lhs, int64_t rhs) {
  return BN_cmp(lhs.bn_.get(), BigNum(rhs).bn_.get()) < 0;
}

bool operator>=(const BigNum& lhs, int64_t rhs) {
  return BN_cmp(lhs.bn_.get(), BigNum(rhs).bn_.get()) >= 0;
}

bool operator<=(const BigNum& lhs, int64_t rhs) {
  return BN_cmp(lhs.bn_.get(), BigNum(rhs).bn_.get()) <= 0;
}

bool operator==(const BigNum& lhs, int64_t rhs) {
  return BN_cmp(lhs.bn_.get(), BigNum(rhs).bn_.get()) == 0;
}

bool operator!=(const BigNum& lhs, int64_t rhs) {
  return BN_cmp(lhs.bn_.get(), BigNum(rhs).bn_.get()) != 0;
}

BigNum operator<<(const BigNum& lhs, size_t shift) {
  YACL_ENFORCE(shift <= std::numeric_limits<int>::max(),
               "Shift value too large: {}", shift);
  BigNum result;
  OSSL_RET_1(BN_lshift(result.bn_.get(), lhs.bn_.get(), shift));
  return result;
}

BigNum operator>>(const BigNum& lhs, size_t shift) {
  YACL_ENFORCE(shift <= std::numeric_limits<int>::max(),
               "Shift value too large: {}", shift);
  BigNum result;
  OSSL_RET_1(BN_rshift(result.bn_.get(), lhs.bn_.get(), shift));
  return result;
}

template <typename FloatType>
void BigNum::SetFloatingPoint(FloatType value) {
  std::modf(value, &value);
  std::string buffer = absl::StrFormat("%.0f", value);
  BIGNUM* bn = nullptr;
  OSSL_RET_NOT_0(BN_dec2bn(&bn, buffer.c_str()));
  bn_.reset(bn);
}

template <typename FloatType>
FloatType BigNum::GetFloatingPoint() const {
  if (BitCount() <= sizeof(BN_ULONG) * 8) {
    BN_ULONG word = BN_get_word(bn_.get());
    auto result = static_cast<FloatType>(word);
    if (BN_is_negative(bn_.get()) != 0) {
      result = -result;
    }
    return result;
  } else {
    char* decimal = BN_bn2dec(bn_.get());
    OSSL_RET_NOT_NULL(decimal);
    FloatType result = atof(decimal);
    OPENSSL_free(decimal);
    return result;
  }
}

template <>
void BigNum::Set(double value) {
  SetFloatingPoint<double>(value);
}

template <>
void BigNum::Set(float value) {
  SetFloatingPoint<float>(value);
}

template <>
double BigNum::Get<double>() const {
  return GetFloatingPoint<double>();
}

template <>
float BigNum::Get<float>() const {
  return GetFloatingPoint<float>();
}

}  // namespace yacl::math::openssl
