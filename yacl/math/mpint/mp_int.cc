// Copyright 2022 Ant Group Co., Ltd.
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

#include "yacl/math/mpint/mp_int.h"

#include "yacl/math/mpint/tommath_ext_features.h"
#include "yacl/math/mpint/tommath_ext_types.h"

extern "C" {
#include "libtommath/tommath_private.h"
}

yacl::math::MPInt operator""_mp(const char *sz, size_t n) {
  return yacl::math::MPInt(std::string(sz, n));
}

yacl::math::MPInt operator""_mp(unsigned long long num) {
  return yacl::math::MPInt(static_cast<uint64_t>(num));
}

namespace yacl::math {

const MPInt MPInt::_0_(0);
const MPInt MPInt::_1_(1);
const MPInt MPInt::_2_(2);

MPInt::MPInt() {
  // Use mpx_init instead of mp_init is hazardous.
  // Therefore, any changes to MPInt’s public interface must be tested
  // carefully.
  mpx_init(&n_);
}

MPInt::MPInt(const std::string &num, size_t radix) {
  MPINT_ENFORCE_OK(mp_init(&n_));
  Set(num, radix);
}

MPInt::MPInt(MPInt &&other) noexcept {
  // /* the infamous mp_int structure */
  // typedef struct {
  //   int used, alloc;
  //   mp_sign sign;
  //   mp_digit *dp;
  // } mp_int;
  n_ = other.n_;
  // NOTE: We've checked mp_clear does nothing if `dp` is nullptr.
  other.n_.dp = nullptr;
}

MPInt::MPInt(const MPInt &other) {
  MPINT_ENFORCE_OK(mp_init_copy(&n_, &other.n_));
}

MPInt &MPInt::operator=(const MPInt &other) {
  MPINT_ENFORCE_OK(mp_copy(&other.n_, &n_));
  return *this;
}

MPInt &MPInt::operator=(MPInt &&other) noexcept {
  std::swap(n_, other.n_);
  return *this;
}

template <>
int8_t MPInt::Get() const {
  return mpx_get_i8(&n_);
}

template <>
int16_t MPInt::Get() const {
  return mpx_get_i16(&n_);
}

template <>
int32_t MPInt::Get() const {
  return mp_get_i32(&n_);
}

template <>
int64_t MPInt::Get() const {
  return mp_get_i64(&n_);
}

template <>
int128_t MPInt::Get() const {
  return mpx_get_i128(&n_);
}

template <>
uint8_t MPInt::Get() const {
  return mpx_get_mag_u8(&n_);
}

template <>
uint16_t MPInt::Get() const {
  return mpx_get_mag_u16(&n_);
}

template <>
uint32_t MPInt::Get() const {
  return mp_get_mag_u32(&n_);
}

template <>
uint64_t MPInt::Get() const {
  return mp_get_mag_u64(&n_);
}

#ifdef __APPLE__
template <>
unsigned long MPInt::Get() const {  // NOLINT: macOS uint64_t is ull
  static_assert(sizeof(unsigned long) == 8);
  return mp_get_mag_u64(&n_);
}
#endif

template <>
uint128_t MPInt::Get() const {
  return mpx_get_mag_u128(&n_);
}

template <>
float MPInt::Get() const {
  return static_cast<float>(mp_get_double(&n_));
}

template <>
double MPInt::Get() const {
  return mp_get_double(&n_);
}

template <>
MPInt MPInt::Get() const {
  return *this;
}

template <>
void MPInt::Set(int8_t value) {
  mpx_set_i8(&n_, value);
}

template <>
void MPInt::Set(int16_t value) {
  mpx_set_i16(&n_, value);
}

template <>
void MPInt::Set(int32_t value) {
  mpx_set_i32(&n_, value);
}

template <>
void MPInt::Set(int64_t value) {
  mpx_set_i64(&n_, value);
}

#ifdef __APPLE__
template <>
void MPInt::Set(long value) {  // NOLINT: macOS int64_t is ll
  static_assert(sizeof(long) == 8);
  mpx_set_i64(&n_, value);
}
#endif

template <>
void MPInt::Set(int128_t value) {
  MPINT_ENFORCE_OK(mp_grow(&n_, 3));
  mpx_set_i128(&n_, value);
}

template <>
void MPInt::Set(uint8_t value) {
  mpx_set_u8(&n_, value);
}

template <>
void MPInt::Set(uint16_t value) {
  mpx_set_u16(&n_, value);
}

template <>
void MPInt::Set(uint32_t value) {
  mpx_set_u32(&n_, value);
}

template <>
void MPInt::Set(uint64_t value) {
  mpx_set_u64(&n_, value);
}

#ifdef __APPLE__
template <>
void MPInt::Set(unsigned long value) {  // NOLINT: macOS uint64_t is ull
  static_assert(sizeof(unsigned long) == 8);
  mpx_set_u64(&n_, value);
}
#endif

template <>
void MPInt::Set(uint128_t value) {
  mpx_set_u128(&n_, value);
}

template <>
void MPInt::Set(float value) {
  MPINT_ENFORCE_OK(mp_set_double(&n_, value));
}

template <>
void MPInt::Set(double value) {
  MPINT_ENFORCE_OK(mp_grow(&n_, 2));
  MPINT_ENFORCE_OK(mp_set_double(&n_, value));
}

template <>
void MPInt::Set(MPInt value) {
  *this = std::move(value);
}

// [mum]: Why not use std::string_view?
// A std::string_view doesn't provide a conversion to a const char* because
// it doesn't store a null-terminated string. It stores a pointer to the
// first element, and the length of the string, basically.
void MPInt::Set(const std::string &num, int radix) {
  auto p = num.c_str();
  auto len = num.size();
  YACL_ENFORCE(len > 0, "Cannot init MPInt by an empty string");

  if (radix > 0) {
    MPINT_ENFORCE_OK(mp_read_radix(&n_, num.c_str(), radix));
    return;
  }

  bool is_neg = false;
  // radix <= 0, auto detect radix
  // https://stackoverflow.com/questions/56881846/get-radix-from-stdstoi
  if (*p == '+' || *p == '-') {
    is_neg = *p == '-';
    ++p;
    --len;
    YACL_ENFORCE(len > 0, "Invalid number string '{}'", num);
  }

  if (*p == '0' && len == 1) {
    SetZero();
    return;
  }

  if (*p != '0') {
    MPINT_ENFORCE_OK(mp_read_radix(&n_, p, 10), "Invalid decimal string: {}",
                     num);
  } else {
    ++p;
    --len;
    if (*p == 'x' || *p == 'X') {
      MPINT_ENFORCE_OK(mp_read_radix(&n_, ++p, 16), "Invalid hex string: {}",
                       num);
    } else {
      MPINT_ENFORCE_OK(mp_read_radix(&n_, p, 8), "Invalid octal string: {}",
                       num);
    }
  }

  if (is_neg) {
    NegateInplace();
  }
}

void MPInt::SetZero() { mp_zero(&n_); }

uint8_t MPInt::operator[](int idx) const { return GetBit(idx); }

uint8_t MPInt::GetBit(int idx) const { return mpx_get_bit(n_, idx); }

void MPInt::SetBit(int idx, uint8_t bit) { mpx_set_bit(&n_, idx, bit); }

size_t MPInt::BitCount() const { return mpx_count_bits_fast(n_); }

bool MPInt::operator>=(const MPInt &other) const { return Compare(other) >= 0; }
bool MPInt::operator<=(const MPInt &other) const { return Compare(other) <= 0; }
bool MPInt::operator>(const MPInt &other) const { return Compare(other) > 0; }
bool MPInt::operator<(const MPInt &other) const { return Compare(other) < 0; }
bool MPInt::operator==(const MPInt &other) const { return Compare(other) == 0; }
bool MPInt::operator!=(const MPInt &other) const { return Compare(other) != 0; }

int MPInt::Compare(const MPInt &other) const { return mp_cmp(&n_, &other.n_); }

int MPInt::CompareAbs(const MPInt &other) const {
  return mp_cmp_mag(&n_, &other.n_);
}

MPInt MPInt::operator+(const MPInt &operand2) const {
  MPInt result;
  MPINT_ENFORCE_OK(mp_add(&n_, &operand2.n_, &result.n_));
  return result;
}

MPInt MPInt::operator-(const MPInt &operand2) const {
  MPInt result;
  MPINT_ENFORCE_OK(mp_sub(&n_, &operand2.n_, &result.n_));
  return result;
}

MPInt MPInt::operator*(const MPInt &operand2) const {
  MPInt result;
  Mul(*this, operand2, &result);
  return result;
}

MPInt MPInt::operator/(const MPInt &operand2) const {
  MPInt result;
  Div(*this, operand2, &result, nullptr);
  return result;
}

MPInt MPInt::operator<<(size_t operand2) const {
  MPInt result;
  MPINT_ENFORCE_OK(mp_mul_2d(&this->n_, operand2, &result.n_));
  return result;
}

MPInt MPInt::operator>>(size_t operand2) const {
  MPInt result;
  MPINT_ENFORCE_OK(mp_div_2d(&this->n_, operand2, &result.n_, nullptr));
  return result;
}

MPInt MPInt::operator%(const MPInt &operand2) const {
  MPInt result;
  Mod(*this, operand2, &result);
  return result;
}

MPInt MPInt::operator-() const {
  MPInt result;
  Negate(&result);
  return result;
}

MPInt MPInt::operator&(const MPInt &operand2) const {
  MPInt result;
  MPINT_ENFORCE_OK(mp_and(&n_, &operand2.n_, &result.n_));
  return result;
}

MPInt MPInt::operator|(const MPInt &operand2) const {
  MPInt result;
  MPINT_ENFORCE_OK(mp_or(&n_, &operand2.n_, &result.n_));
  return result;
}

MPInt MPInt::operator^(const MPInt &operand2) const {
  MPInt result;
  MPINT_ENFORCE_OK(mp_xor(&n_, &operand2.n_, &result.n_));
  return result;
}

MPInt MPInt::operator+=(const MPInt &operand2) {
  MPINT_ENFORCE_OK(mp_add(&n_, &operand2.n_, &n_));
  return *this;
}

MPInt MPInt::operator-=(const MPInt &operand2) {
  MPINT_ENFORCE_OK(mp_sub(&n_, &operand2.n_, &n_));
  return *this;
}

MPInt MPInt::operator*=(const MPInt &operand2) {
  MPINT_ENFORCE_OK(mp_mul(&n_, &operand2.n_, &n_));
  return *this;
}

MPInt MPInt::operator/=(const MPInt &operand2) {
  MPINT_ENFORCE_OK(mp_div(&n_, &operand2.n_, &n_, nullptr));
  return *this;
}

MPInt MPInt::operator%=(const MPInt &operand2) {
  MPINT_ENFORCE_OK(mp_mod(&n_, &operand2.n_, &n_));
  return *this;
}

MPInt MPInt::operator<<=(size_t operand2) {
  MPINT_ENFORCE_OK(mp_mul_2d(&this->n_, operand2, &this->n_));
  return *this;
}

MPInt MPInt::operator>>=(size_t operand2) {
  MPINT_ENFORCE_OK(mp_div_2d(&this->n_, operand2, &this->n_, nullptr));
  return *this;
}

MPInt MPInt::operator&=(const MPInt &operand2) {
  MPINT_ENFORCE_OK(mp_and(&n_, &operand2.n_, &n_));
  return *this;
}

MPInt MPInt::operator|=(const MPInt &operand2) {
  MPINT_ENFORCE_OK(mp_or(&n_, &operand2.n_, &n_));
  return *this;
}

MPInt MPInt::operator^=(const MPInt &operand2) {
  MPINT_ENFORCE_OK(mp_xor(&n_, &operand2.n_, &n_));
  return *this;
}

std::ostream &operator<<(std::ostream &os, const MPInt &an_int) {
  return os << an_int.ToString();
}

MPInt &MPInt::DecrOne() & {
  mpx_reserve(&n_, 1);
  MPINT_ENFORCE_OK(mp_decr(&n_));
  return *this;
}

MPInt &MPInt::IncrOne() & {
  mpx_reserve(&n_, 1);
  MPINT_ENFORCE_OK(mp_incr(&n_));
  return *this;
}

MPInt &&MPInt::DecrOne() && {
  mpx_reserve(&n_, 1);
  MPINT_ENFORCE_OK(mp_decr(&n_));
  return std::move(*this);
}

MPInt &&MPInt::IncrOne() && {
  mpx_reserve(&n_, 1);
  MPINT_ENFORCE_OK(mp_incr(&n_));
  return std::move(*this);
}

MPInt MPInt::Abs() const {
  MPInt result;
  MPINT_ENFORCE_OK(mp_abs(&n_, &result.n_));
  return result;
}

void MPInt::Add(const MPInt &a, const MPInt &b, MPInt *c) {
  MPINT_ENFORCE_OK(mp_add(&a.n_, &b.n_, &c->n_));
}

MPInt MPInt::AddMod(const MPInt &b, const MPInt &mod) const {
  MPInt res;
  MPINT_ENFORCE_OK(mp_addmod(&n_, &b.n_, &mod.n_, &res.n_));
  return res;
}

void MPInt::AddMod(const yacl::math::MPInt &a, const yacl::math::MPInt &b,
                   const yacl::math::MPInt &mod, yacl::math::MPInt *d) {
  MPINT_ENFORCE_OK(mp_addmod(&a.n_, &b.n_, &mod.n_, &d->n_));
}

void MPInt::Sub(const MPInt &a, const MPInt &b, MPInt *c) {
  MPINT_ENFORCE_OK(mp_sub(&a.n_, &b.n_, &c->n_));
}

MPInt MPInt::SubMod(const MPInt &b, const MPInt &mod) const {
  MPInt res;
  MPINT_ENFORCE_OK(mp_submod(&n_, &b.n_, &mod.n_, &res.n_));
  return res;
}

void MPInt::SubMod(const MPInt &a, const MPInt &b, const MPInt &mod, MPInt *d) {
  MPINT_ENFORCE_OK(mp_submod(&a.n_, &b.n_, &mod.n_, &d->n_));
}

void MPInt::Mul(const MPInt &a, const MPInt &b, MPInt *c) {
  MPINT_ENFORCE_OK(mp_mul(&a.n_, &b.n_, &c->n_));
}

MPInt MPInt::Mul(mp_digit b) const {
  MPInt res;
  MPINT_ENFORCE_OK(mp_mul_d(&n_, b, &res.n_));
  return res;
}

void MPInt::MulInplace(mp_digit b) { MPINT_ENFORCE_OK(mp_mul_d(&n_, b, &n_)); }

MPInt MPInt::MulMod(const MPInt &b, const MPInt &mod) const {
  MPInt res;
  MPINT_ENFORCE_OK(mp_mulmod(&n_, &b.n_, &mod.n_, &res.n_));
  return res;
}

void MPInt::MulMod(const MPInt &a, const MPInt &b, const MPInt &mod, MPInt *d) {
  MPINT_ENFORCE_OK(mp_mulmod(&a.n_, &b.n_, &mod.n_, &d->n_));
}

void MPInt::Pow(const MPInt &a, uint32_t b, MPInt *c) {
  if (b == 0) {
    *c = MPInt::_1_;
    return;
  }

  mpx_reserve(&c->n_, MP_BITS_TO_DIGITS(mpx_count_bits_fast(a.n_) * b));
  MPINT_ENFORCE_OK(mp_expt_n(&a.n_, b, &c->n_));
}

MPInt MPInt::Pow(uint32_t b) const {
  if (b == 0) {
    YACL_ENFORCE(!IsZero(), "Power: 0^0 is illegal");
    return MPInt::_1_;
  }

  MPInt res;
  mpx_reserve(&res.n_, MP_BITS_TO_DIGITS(mpx_count_bits_fast(n_) * b));
  MPINT_ENFORCE_OK(mp_expt_n(&n_, b, &res.n_));
  return res;
}

void MPInt::PowInplace(uint32_t b) { MPINT_ENFORCE_OK(mp_expt_n(&n_, b, &n_)); }

MPInt MPInt::PowMod(const MPInt &b, const MPInt &mod) const {
  MPInt res;
  MPINT_ENFORCE_OK(mp_exptmod(&n_, &b.n_, &mod.n_, &res.n_));
  return res;
}

void MPInt::PowMod(const MPInt &a, const MPInt &b, const MPInt &mod, MPInt *d) {
  MPINT_ENFORCE_OK(mp_exptmod(&a.n_, &b.n_, &mod.n_, &d->n_));
}

void MPInt::Lcm(const MPInt &a, const MPInt &b, MPInt *c) {
  MPINT_ENFORCE_OK(mp_lcm(&a.n_, &b.n_, &c->n_));
}

void MPInt::Gcd(const MPInt &a, const MPInt &b, MPInt *c) {
  MPINT_ENFORCE_OK(mp_gcd(&a.n_, &b.n_, &c->n_));
}

/* a/b => cb + d == a */
void MPInt::Div(const MPInt &a, const MPInt &b, MPInt *c, MPInt *d) {
  mp_int *c_repl = (c == nullptr) ? nullptr : &c->n_;
  mp_int *d_repl = (d == nullptr) ? nullptr : &d->n_;
  MPINT_ENFORCE_OK(mp_div(&a.n_, &b.n_, c_repl, d_repl));
}

void MPInt::Div3(const MPInt &a, MPInt *b) {
  MPINT_ENFORCE_OK(s_mp_div_3(&a.n_, &b->n_, nullptr));
}

void MPInt::InvertMod(const MPInt &a, const MPInt &mod, MPInt *c) {
  MPINT_ENFORCE_OK(mp_invmod(&a.n_, &mod.n_, &c->n_));
}

MPInt MPInt::InvertMod(const MPInt &mod) const {
  MPInt res(0, mod.BitCount());
  InvertMod(*this, mod, &res);
  return res;
}

void MPInt::Mod(const MPInt &a, const MPInt &mod, MPInt *c) {
  MPINT_ENFORCE_OK(mp_mod(&a.n_, &mod.n_, &c->n_));
}

MPInt MPInt::Mod(const yacl::math::MPInt &mod) const {
  MPInt res(0, mod.BitCount());
  Mod(*this, mod, &res);
  return res;
}

void MPInt::RandomRoundDown(size_t bit_size, MPInt *r) {
  // floor (向下取整)
  mp_int *n = &r->n_;
  MPINT_ENFORCE_OK(mp_rand(n, bit_size / MP_DIGIT_BIT));
}

void MPInt::RandomRoundUp(size_t bit_size, MPInt *r) {
  // ceil (向上取整)
  mp_int *n = &r->n_;
  MPINT_ENFORCE_OK(mp_rand(n, (bit_size + MP_DIGIT_BIT - 1) / MP_DIGIT_BIT));
}

void MPInt::RandomExactBits(size_t bit_size, MPInt *r) {
  mpx_rand_bits(&r->n_, bit_size);
}

void MPInt::RandomMonicExactBits(size_t bit_size, MPInt *r) {
  YACL_ENFORCE(bit_size > 0, "cannot gen monic random number of size 0");
  do {
    RandomExactBits(bit_size, r);
  } while (r->BitCount() != bit_size);
}

void MPInt::RandomLtN(const MPInt &n, MPInt *r) {
  do {
    MPInt::RandomExactBits(n.BitCount(), r);
  } while (r->IsNegative() || r->Compare(n) >= 0);
}

void MPInt::RandPrimeOver(size_t bit_size, MPInt *out, PrimeType prime_type) {
  YACL_ENFORCE_GT(bit_size, 81U, "bit_size must >= 82");
  int trials = mp_prime_rabin_miller_trials(bit_size);

  if (prime_type == PrimeType::FastSafe) {
    mpx_safe_prime_rand(&out->n_, trials, bit_size);
  } else {
    MPINT_ENFORCE_OK(mp_prime_rand(&out->n_, trials, bit_size,
                                   static_cast<int>(prime_type)));
  }
}

bool MPInt::IsPrime() const {
  int trials = mp_prime_rabin_miller_trials(BitCount());
  bool result;
  MPINT_ENFORCE_OK(mp_prime_is_prime(&n_, trials, &result));
  return result > 0;
}

// todo: this function is very slow.
std::string MPInt::ToRadixString(int radix) const {
  size_t size = 0;
  MPINT_ENFORCE_OK(mp_radix_size(&n_, radix, &size));

  std::string output;
  output.resize(size);
  MPINT_ENFORCE_OK(mp_to_radix(&n_, output.data(), size, nullptr, radix));
  output.pop_back();  // remove tailing '\0'
  return output;
}

std::string MPInt::ToHexString() const { return ToRadixString(16); }

std::string MPInt::ToString() const { return ToRadixString(10); }

yacl::Buffer MPInt::Serialize() const {
  size_t size = mpx_serialize_size(n_);
  yacl::Buffer buffer(size);
  mpx_serialize(n_, buffer.data<uint8_t>(), size);
  return buffer;
}

size_t MPInt::Serialize(uint8_t *buf, size_t buf_len) const {
  if (buf == nullptr) {
    return mpx_serialize_size(n_);
  }

  return mpx_serialize(n_, buf, buf_len);
}

void MPInt::Deserialize(yacl::ByteContainerView buffer) {
  mpx_deserialize(&n_, buffer.data(), buffer.size());
}

yacl::Buffer MPInt::ToBytes(size_t byte_len, Endian endian) const {
  yacl::Buffer buf(byte_len);
  ToBytes(buf.data<unsigned char>(), byte_len, endian);
  return buf;
}

void MPInt::ToBytes(unsigned char *buf, size_t buf_len, Endian endian) const {
  mpx_to_bytes(n_, buf, buf_len, endian);
}

yacl::Buffer MPInt::ToMagBytes(Endian endian) const {
  size_t size = mpx_mag_bytes_size(n_);
  yacl::Buffer buffer(size);
  mpx_to_mag_bytes(n_, buffer.data<uint8_t>(), size, endian);
  return buffer;
}

// If buf_len is too small, an exception will be thrown.
// If buf_len exceeds the actual required size, considering the
// characteristics of big-endian, the remaining part will not be assigned 0.
size_t MPInt::ToMagBytes(unsigned char *buf, size_t buf_len,
                         Endian endian) const {
  if (buf == nullptr) {
    return mpx_mag_bytes_size(n_);
  }

  return mpx_to_mag_bytes(n_, buf, buf_len, endian);
}

void MPInt::FromMagBytes(yacl::ByteContainerView buffer, Endian endian) {
  mpx_from_mag_bytes(&n_, buffer.data(), buffer.size(), endian);
}

}  // namespace yacl::math
