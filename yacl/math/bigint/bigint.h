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

#pragma once

#include "yacl/math/bigint/bigint_spi.h"
#include "yacl/math/bigint/bigint_var.h"

namespace yacl::math {

class BigInt : public BigIntVar {
 public:
  using BigIntVar::BigIntVar;

  template <typename... ArgTypes>
  static BigInt NewBigInt(const std::shared_ptr<IBigIntLib>& lib,
                          ArgTypes&&... args) {
    return lib->NewBigInt(std::forward<ArgTypes>(args)...);
  }

  BigInt() : BigInt(BigIntLibFactory::DefaultBigIntLib()) {}

  BigInt(const std::string& str, int base)
      : BigInt(str, base, BigIntLibFactory::DefaultBigIntLib()) {}

  template <typename T, typename = std::enable_if_t<std::is_arithmetic_v<T>>>
  explicit BigInt(T v) : BigInt(v, BigIntLibFactory::DefaultBigIntLib()) {}

  template <typename T, typename = std::enable_if_t<std::is_arithmetic_v<T>>>
  BigInt(T v, size_t reserved_bits)
      : BigInt(v, reserved_bits, BigIntLibFactory::DefaultBigIntLib()) {}

  explicit BigInt(const std::shared_ptr<IBigIntLib>& lib)
      : BigInt(NewBigInt(lib)) {}

  BigInt(const std::string& str, int base,
         const std::shared_ptr<IBigIntLib>& lib)
      : BigInt(NewBigInt(lib, str, base)) {}

  template <typename T, typename = std::enable_if_t<std::is_arithmetic_v<T>>>
  BigInt(T v, const std::shared_ptr<IBigIntLib>& lib) : BigInt(lib) {
    Set(v);
  }

  template <typename T, typename = std::enable_if_t<std::is_arithmetic_v<T>>>
  BigInt(T v, size_t reserved_bits, const std::shared_ptr<IBigIntLib>& lib)
      : BigInt(NewBigInt(lib, reserved_bits)) {
    Set(v);
  }

  BigInt(const BigIntVar& other) : BigIntVar(other) {}        // NOLINT
  BigInt(BigIntVar&& other) : BigIntVar(std::move(other)) {}  // NOLINT

  // T could be (u)int8/16/32/64/128 or float/double
  template <typename T, typename = std::enable_if_t<std::is_arithmetic_v<T>>>
  BigInt& operator=(T value) {
    Set(value);
    return *this;
  }

  void Set(const std::string& num, int radix);

  // T could be (u)int8/16/32/64/128 or float/double
  template <typename T>
  void Set(T value) {
    std::visit([value](auto& a) { a.template Set<T>(value); }, *this);
  }

  // T could be (u)int8/16/32/64/128
  template <typename T>
  [[nodiscard]] T Get() const {
    return std::visit([](auto& a) { return a.template Get<T>(); }, *this);
  }

  BigInt& operator+=(const BigInt& b);
  BigInt& operator-=(const BigInt& b);
  BigInt& operator*=(const BigInt& b);

  // Round the quotient down towards −infinity
  // The remainder will have the same sign as the divisor
  BigInt& operator/=(const BigInt& b);
  BigInt& operator%=(const BigInt& b);

  BigInt& operator+=(uint64_t b);
  BigInt& operator-=(uint64_t b);
  BigInt& operator*=(uint64_t b);

  // Round the quotient down towards −infinity
  // The remainder will have the same sign as the divisor
  BigInt& operator/=(uint64_t b);

  BigInt& operator&=(const BigInt& b);
  BigInt& operator|=(const BigInt& b);
  BigInt& operator^=(const BigInt& b);

  BigInt& operator<<=(size_t b);
  BigInt& operator>>=(size_t b);

  BigInt& operator++();
  BigInt operator++(int);
  BigInt& operator--();
  BigInt operator--(int);

  [[nodiscard]] BigInt operator-() const;
  void NegateInplace();

  [[nodiscard]] BigInt Pow(uint32_t e) const;
  void PowInplace(uint32_t e);

  // Compare |a| to |b|
  // Returns:
  //  < 0 if |a| < |b|
  //  0 if |a| == |b|
  //  > 0 if |a| > |b|
  [[nodiscard]] int CompareAbs(const BigInt& b) const;
  [[nodiscard]] int CompareAbs(int64_t b) const;

  [[nodiscard]] BigInt Abs() const;

  [[nodiscard]] size_t BitCount() const;

  [[nodiscard]] bool IsPositive() const;
  [[nodiscard]] bool IsNegative() const;
  [[nodiscard]] bool IsZero() const;
  [[nodiscard]] bool IsOdd() const;
  [[nodiscard]] bool IsPrime() const;

  // Select a random r in [0, n)
  [[nodiscard]] static BigInt RandomLtN(const BigInt& n);
  static void RandomLtN(const BigInt& n, BigInt* r);

  // Generate an exact bit_size random number, the msb is not guaranteed to
  // be 1
  [[nodiscard]] static BigInt RandomExactBits(size_t bit_size);
  static void RandomExactBits(size_t bit_size, BigInt* r);

  // Generate an exact bit_size random number with the highest bit being 1.
  [[nodiscard]] static BigInt RandomMonicExactBits(size_t bit_size);

  // Generate a random prime number of "bit_size" size
  [[nodiscard]] static BigInt RandPrimeOver(
      size_t bit_size, PrimeType prime_type = PrimeType::BBS);

  [[nodiscard]] static std::unique_ptr<MontgomerySpace> CreateMontgomerySpace(
      const BigInt& mod);

  [[nodiscard]] BigInt Lcm(const BigInt& b) const;
  [[nodiscard]] BigInt Gcd(const BigInt& b) const;

  [[nodiscard]] BigInt AddMod(const BigInt& b, const BigInt& m) const;
  [[nodiscard]] BigInt SubMod(const BigInt& b, const BigInt& m) const;
  [[nodiscard]] BigInt MulMod(const BigInt& b, const BigInt& m) const;
  [[nodiscard]] BigInt InvMod(const BigInt& m) const;
  [[nodiscard]] BigInt PowMod(const BigInt& e, const BigInt& m) const;

  [[nodiscard]] std::string ToString() const;
  [[nodiscard]] std::string ToHexString() const;

  [[nodiscard]] yacl::Buffer ToBytes(size_t byte_len,
                                     Endian endian = Endian::native) const;
  void ToBytes(unsigned char* buf, size_t buf_len,
               Endian endian = Endian::native) const;
  size_t ToMagBytes(unsigned char* buf, size_t buf_len,
                    Endian endian = Endian::native) const;
  void FromMagBytes(yacl::ByteContainerView buffer,
                    Endian endian = Endian::native);

  [[nodiscard]] uint8_t GetBit(size_t idx) const;
  void SetBit(size_t idx, uint8_t bit);

  [[nodiscard]] yacl::Buffer Serialize() const;
  size_t Serialize(uint8_t* buf, size_t buf_len) const;
  void Deserialize(yacl::ByteContainerView buffer);

  friend BigInt operator+(const BigInt& a, const BigInt& b);
  friend BigInt operator-(const BigInt& a, const BigInt& b);
  friend BigInt operator*(const BigInt& a, const BigInt& b);

  // Round the quotient down towards −infinity
  // The remainder will have the same sign as the divisor
  friend BigInt operator/(const BigInt& a, const BigInt& b);
  friend BigInt operator%(const BigInt& a, const BigInt& b);

  friend BigInt operator+(const BigInt& a, uint64_t b);
  friend BigInt operator-(const BigInt& a, uint64_t b);
  friend BigInt operator*(const BigInt& a, uint64_t b);

  // Round the quotient down towards −infinity
  // The remainder will have the same sign as the divisor
  friend BigInt operator/(const BigInt& a, uint64_t b);
  friend uint64_t operator%(const BigInt& a, uint64_t b);

  friend BigInt operator&(const BigInt& a, const BigInt& b);
  friend BigInt operator|(const BigInt& a, const BigInt& b);
  friend BigInt operator^(const BigInt& a, const BigInt& b);

  friend BigInt operator<<(const BigInt& a, size_t b);
  friend BigInt operator>>(const BigInt& a, size_t b);

  friend bool operator>(const BigInt& a, const BigInt& b);
  friend bool operator<(const BigInt& a, const BigInt& b);
  friend bool operator>=(const BigInt& a, const BigInt& b);
  friend bool operator<=(const BigInt& a, const BigInt& b);
  friend bool operator==(const BigInt& a, const BigInt& b);
  friend bool operator!=(const BigInt& a, const BigInt& b);

  friend bool operator>(const BigInt& a, int64_t b);
  friend bool operator<(const BigInt& a, int64_t b);
  friend bool operator>=(const BigInt& a, int64_t b);
  friend bool operator<=(const BigInt& a, int64_t b);
  friend bool operator==(const BigInt& a, int64_t b);
  friend bool operator!=(const BigInt& a, int64_t b);

  friend std::ostream& operator<<(std::ostream& os, const BigInt& a);
};

// For fmtlib
inline auto format_as(const BigInt& n) { return fmt::streamed(n); }

}  // namespace yacl::math

template <>
struct std::hash<yacl::math::BigInt> {
  size_t operator()(const yacl::math::BigInt& x) const {
    return std::visit(
        [](const auto& a) { return std::hash<std::decay_t<decltype(a)>>{}(a); },
        x);
  }
};

namespace msgpack {
MSGPACK_API_VERSION_NAMESPACE(MSGPACK_DEFAULT_API_NS) {
  namespace adaptor {

  template <>
  struct pack<yacl::math::BigInt> {
    template <typename Stream>
    msgpack::packer<Stream>& operator()(msgpack::packer<Stream>& object,
                                        const yacl::math::BigInt& n) const {
      object.pack(std::string_view(n.Serialize()));
      return object;
    }
  };

  template <>
  struct convert<yacl::math::BigInt> {
    const msgpack::object& operator()(const msgpack::object& object,
                                      yacl::math::BigInt& n) const {
      n.Deserialize(object.as<std::string_view>());
      return object;
    }
  };

  }  // namespace adaptor
}  // MSGPACK_API_VERSION_NAMESPACE(MSGPACK_DEFAULT_API_NS)
}  // namespace msgpack
