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

#include "yacl/math/bigint/bigint.h"

namespace yacl::math {

namespace {

template <typename RetType, typename Op>
RetType ApplyBinaryOp(const BigInt& a, const BigInt& b, Op op) {
  return std::visit(
      [op](const auto& a, const auto& b) -> RetType {
        if constexpr (std::is_same_v<decltype(a), decltype(b)>) {
          return op(a, b);
        } else {
          YACL_THROW("BigInt inner type mismatch: {} and {}", typeid(a).name(),
                     typeid(b).name());
        }
      },
      a, b);
}

template <typename Op>
BigInt ApplyTernaryOp(const BigInt& a, const BigInt& b, const BigInt& c,
                      Op op) {
  return std::visit(
      [op](const auto& a, const auto& b, const auto& c) -> BigInt {
        if constexpr (std::is_same_v<decltype(a), decltype(b)> &&
                      std::is_same_v<decltype(b), decltype(c)>) {
          return op(a, b, c);
        } else {
          YACL_THROW("BigInt inner type mismatch: {} and {} and {}",
                     typeid(a).name(), typeid(b).name(), typeid(c).name());
        }
      },
      a, b, c);
}

template <typename Op>
void ApplyCompAssignOp(BigInt& a, const BigInt& b, Op op) {
  std::visit(
      [op](auto& a, const auto& b) {
        if constexpr (std::is_convertible_v<decltype(a), decltype(b)>) {
          op(a, b);
        } else {
          YACL_THROW("BigInt::operator type mismatch: {} and {}",
                     typeid(a).name(), typeid(b).name());
        }
      },
      a, b);
}

}  // namespace

void BigInt::Set(const std::string& num, int radix) {
  std::visit([num, radix](auto& a) { a.Set(num, radix); }, *this);
}

void BigInt::NegateInplace() {
  std::visit([](auto& a) { a.NegateInplace(); }, *this);
}

BigInt BigInt::Pow(uint32_t e) const {
  return std::visit([e](const auto& a) -> BigInt { return a.Pow(e); }, *this);
}

void BigInt::PowInplace(uint32_t e) {
  std::visit([e](auto& a) { a.PowInplace(e); }, *this);
}

int BigInt::CompareAbs(const BigInt& b) const {
  return ApplyBinaryOp<int>(
      *this, b, [](const auto& a, const auto& b) { return a.CompareAbs(b); });
}

int BigInt::CompareAbs(int64_t b) const {
  return std::visit([b](const auto& a) { return a.CompareAbs(b); }, *this);
}

BigInt BigInt::Abs() const {
  return std::visit([](const auto& a) -> BigInt { return a.Abs(); }, *this);
}

size_t BigInt::BitCount() const {
  return std::visit([](const auto& a) { return a.BitCount(); }, *this);
}

bool BigInt::IsPositive() const {
  return std::visit(
      [](const auto& a) { return !a.IsNegative() && !a.IsZero(); }, *this);
}

bool BigInt::IsNegative() const {
  return std::visit([](const auto& a) { return a.IsNegative(); }, *this);
}

bool BigInt::IsZero() const {
  return std::visit([](const auto& a) { return a.IsZero(); }, *this);
}

bool BigInt::IsOdd() const {
  return std::visit([](const auto& a) { return a.IsOdd(); }, *this);
}

bool BigInt::IsPrime() const {
  return std::visit([](const auto& a) { return a.IsPrime(); }, *this);
}

BigInt BigInt::RandomLtN(const BigInt& n) {
  return std::visit([](const auto& n) -> BigInt { return n.RandomLtN(n); }, n);
}

void BigInt::RandomLtN(const BigInt& n, BigInt* r) { *r = RandomLtN(n); }

BigInt BigInt::RandomExactBits(size_t bit_size) {
  return BigIntLibFactory::DefaultBigIntLib()->RandomExactBits(bit_size);
}

void BigInt::RandomExactBits(size_t bit_size, BigInt* r) {
  *r = BigIntLibFactory::DefaultBigIntLib()->RandomExactBits(bit_size);
}

BigInt BigInt::RandomMonicExactBits(size_t bit_size) {
  return BigIntLibFactory::DefaultBigIntLib()->RandomMonicExactBits(bit_size);
}

BigInt BigInt::RandPrimeOver(size_t bit_size, PrimeType prime_type) {
  return BigIntLibFactory::DefaultBigIntLib()->RandPrimeOver(bit_size,
                                                             prime_type);
}

std::unique_ptr<MontgomerySpace> BigInt::CreateMontgomerySpace(
    const BigInt& mod) {
  return BigIntLibFactory::DefaultBigIntLib()->CreateMontgomerySpace(mod);
}

BigInt BigInt::Lcm(const BigInt& b) const {
  return ApplyBinaryOp<BigInt>(
      *this, b, [](const auto& a, const auto& b) { return a.Lcm(a, b); });
}

BigInt BigInt::Gcd(const BigInt& b) const {
  return ApplyBinaryOp<BigInt>(
      *this, b, [](const auto& a, const auto& b) { return a.Gcd(a, b); });
}

BigInt BigInt::AddMod(const BigInt& b, const BigInt& mod) const {
  return ApplyTernaryOp(*this, b, mod,
                        [](const auto& a, const auto& b, const auto& c) {
                          return a.AddMod(b, c);
                        });
}

BigInt BigInt::SubMod(const BigInt& b, const BigInt& mod) const {
  return ApplyTernaryOp(*this, b, mod,
                        [](const auto& a, const auto& b, const auto& c) {
                          return a.SubMod(b, c);
                        });
}

BigInt BigInt::MulMod(const BigInt& b, const BigInt& mod) const {
  return ApplyTernaryOp(*this, b, mod,
                        [](const auto& a, const auto& b, const auto& c) {
                          return a.MulMod(b, c);
                        });
}

BigInt BigInt::InvMod(const BigInt& mod) const {
  return ApplyBinaryOp<BigInt>(
      *this, mod, [](const auto& a, const auto& mod) { return a.InvMod(mod); });
}

BigInt BigInt::PowMod(const BigInt& e, const BigInt& mod) const {
  return ApplyTernaryOp(*this, e, mod,
                        [](const auto& a, const auto& e, const auto& mod) {
                          return a.PowMod(e, mod);
                        });
}

std::string BigInt::ToString() const {
  return std::visit([](const auto& a) { return a.ToString(); }, *this);
}

std::string BigInt::ToHexString() const {
  return std::visit([](const auto& a) { return a.ToHexString(); }, *this);
}

yacl::Buffer BigInt::ToBytes(size_t byte_len, Endian endian) const {
  return std::visit(
      [byte_len, endian](const auto& a) { return a.ToBytes(byte_len, endian); },
      *this);
}

void BigInt::ToBytes(unsigned char* buf, size_t buf_len, Endian endian) const {
  std::visit([buf, buf_len,
              endian](const auto& a) { a.ToBytes(buf, buf_len, endian); },
             *this);
}

size_t BigInt::ToMagBytes(unsigned char* buf, size_t buf_len,
                          Endian endian) const {
  return std::visit(
      [buf, buf_len, endian](const auto& a) {
        return a.ToMagBytes(buf, buf_len, endian);
      },
      *this);
}

void BigInt::FromMagBytes(yacl::ByteContainerView buffer, Endian endian) {
  std::visit([buffer, endian](auto& a) { a.FromMagBytes(buffer, endian); },
             *this);
}

uint8_t BigInt::GetBit(size_t idx) const {
  return std::visit([idx](const auto& a) { return a.GetBit(idx); }, *this);
}

void BigInt::SetBit(size_t idx, uint8_t bit) {
  std::visit([idx, bit](auto& a) { a.SetBit(idx, bit); }, *this);
}

Buffer BigInt::Serialize() const {
  return std::visit([](const auto& a) { return a.Serialize(); }, *this);
}

size_t BigInt::Serialize(uint8_t* buf, size_t buf_len) const {
  return std::visit(
      [buf, buf_len](const auto& a) { return a.Serialize(buf, buf_len); },
      *this);
}

void BigInt::Deserialize(ByteContainerView buffer) {
  std::visit([buffer](auto& a) { a.Deserialize(buffer); }, *this);
}

BigInt& BigInt::operator+=(const BigInt& b) {
  ApplyCompAssignOp(*this, b, [](auto& a, const auto& b) { a += b; });
  return *this;
}

BigInt& BigInt::operator-=(const BigInt& b) {
  ApplyCompAssignOp(*this, b, [](auto& a, const auto& b) { a -= b; });
  return *this;
}

BigInt& BigInt::operator*=(const BigInt& b) {
  ApplyCompAssignOp(*this, b, [](auto& a, const auto& b) { a *= b; });
  return *this;
}

BigInt& BigInt::operator/=(const BigInt& b) {
  ApplyCompAssignOp(*this, b, [](auto& a, const auto& b) { a /= b; });
  return *this;
}

BigInt& BigInt::operator%=(const BigInt& b) {
  ApplyCompAssignOp(*this, b, [](auto& a, const auto& b) { a %= b; });
  return *this;
}

BigInt& BigInt::operator+=(uint64_t b) {
  std::visit([b](auto& a) { a += b; }, *this);
  return *this;
}

BigInt& BigInt::operator-=(uint64_t b) {
  std::visit([b](auto& a) { a -= b; }, *this);
  return *this;
}

BigInt& BigInt::operator*=(uint64_t b) {
  std::visit([b](auto& a) { a *= b; }, *this);
  return *this;
}

BigInt& BigInt::operator/=(uint64_t b) {
  std::visit([b](auto& a) { a /= b; }, *this);
  return *this;
}

BigInt& BigInt::operator&=(const BigInt& b) {
  ApplyCompAssignOp(*this, b, [](auto& a, const auto& b) { a &= b; });
  return *this;
}

BigInt& BigInt::operator|=(const BigInt& b) {
  ApplyCompAssignOp(*this, b, [](auto& a, const auto& b) { a |= b; });
  return *this;
}

BigInt& BigInt::operator^=(const BigInt& b) {
  ApplyCompAssignOp(*this, b, [](auto& a, const auto& b) { a ^= b; });
  return *this;
}

BigInt& BigInt::operator<<=(size_t b) {
  std::visit([b](auto& a) { a <<= b; }, *this);
  return *this;
}

BigInt& BigInt::operator>>=(size_t b) {
  std::visit([b](auto& a) { a >>= b; }, *this);
  return *this;
}

BigInt& BigInt::operator++() {
  std::visit([](auto& a) { ++a; }, *this);
  return *this;
}

BigInt BigInt::operator++(int) {
  BigInt r = *this;
  std::visit([](auto& a) { ++a; }, *this);
  return r;
}

BigInt& BigInt::operator--() {
  std::visit([](auto& a) { --a; }, *this);
  return *this;
}

BigInt BigInt::operator--(int) {
  BigInt r = *this;
  std::visit([](auto& a) { --a; }, *this);
  return r;
}

BigInt BigInt::operator-() const {
  return std::visit([](const auto& a) -> BigInt { return -a; }, *this);
}

BigInt operator+(const BigInt& a, const BigInt& b) {
  return ApplyBinaryOp<BigInt>(a, b, std::plus<>());
}

BigInt operator-(const BigInt& a, const BigInt& b) {
  return ApplyBinaryOp<BigInt>(a, b, std::minus<>());
}

BigInt operator*(const BigInt& a, const BigInt& b) {
  return ApplyBinaryOp<BigInt>(a, b, std::multiplies<>());
}

BigInt operator/(const BigInt& a, const BigInt& b) {
  return ApplyBinaryOp<BigInt>(a, b, std::divides<>());
}

BigInt operator%(const BigInt& a, const BigInt& b) {
  return ApplyBinaryOp<BigInt>(a, b, std::modulus<>());
}

BigInt operator+(const BigInt& a, uint64_t b) {
  return std::visit([b](const auto& a) -> BigInt { return a + b; }, a);
}

BigInt operator-(const BigInt& a, uint64_t b) {
  return std::visit([b](const auto& a) -> BigInt { return a - b; }, a);
}

BigInt operator*(const BigInt& a, uint64_t b) {
  return std::visit([b](const auto& a) -> BigInt { return a * b; }, a);
}

BigInt operator/(const BigInt& a, uint64_t b) {
  return std::visit([b](const auto& a) -> BigInt { return a / b; }, a);
}

uint64_t operator%(const BigInt& a, uint64_t b) {
  return std::visit([b](const auto& a) -> uint64_t { return a % b; }, a);
}

BigInt operator&(const BigInt& a, const BigInt& b) {
  return ApplyBinaryOp<BigInt>(a, b, std::bit_and<>());
}

BigInt operator|(const BigInt& a, const BigInt& b) {
  return ApplyBinaryOp<BigInt>(a, b, std::bit_or<>());
}

BigInt operator^(const BigInt& a, const BigInt& b) {
  return ApplyBinaryOp<BigInt>(a, b, std::bit_xor<>());
}

bool operator>(const BigInt& a, const BigInt& b) {
  return ApplyBinaryOp<bool>(a, b, std::greater<>());
}

bool operator<(const BigInt& a, const BigInt& b) {
  return ApplyBinaryOp<bool>(a, b, std::less<>());
}

bool operator>=(const BigInt& a, const BigInt& b) {
  return ApplyBinaryOp<bool>(a, b, std::greater_equal<>());
}

bool operator<=(const BigInt& a, const BigInt& b) {
  return ApplyBinaryOp<bool>(a, b, std::less_equal<>());
}

bool operator==(const BigInt& a, const BigInt& b) {
  return ApplyBinaryOp<bool>(a, b, std::equal_to<>());
}

bool operator!=(const BigInt& a, const BigInt& b) {
  return ApplyBinaryOp<bool>(a, b, std::not_equal_to<>());
}

bool operator>(const BigInt& a, int64_t b) {
  return std::visit([b](const auto& a) { return a > b; }, a);
}

bool operator<(const BigInt& a, int64_t b) {
  return std::visit([b](const auto& a) { return a < b; }, a);
}

bool operator>=(const BigInt& a, int64_t b) {
  return std::visit([b](const auto& a) { return a >= b; }, a);
}

bool operator<=(const BigInt& a, int64_t b) {
  return std::visit([b](const auto& a) { return a <= b; }, a);
}

bool operator==(const BigInt& a, int64_t b) {
  return std::visit([b](const auto& a) { return a == b; }, a);
}

bool operator!=(const BigInt& a, int64_t b) {
  return std::visit([b](const auto& a) { return a != b; }, a);
}

BigInt operator<<(const BigInt& a, size_t b) {
  return std::visit([b](const auto& a) -> BigInt { return a << b; }, a);
}

BigInt operator>>(const BigInt& a, size_t b) {
  return std::visit([b](const auto& a) -> BigInt { return a >> b; }, a);
}

std::ostream& operator<<(std::ostream& os, const BigInt& a) {
  return os << a.ToString();
}

}  // namespace yacl::math
