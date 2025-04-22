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

#include <functional>

#include "openssl/bn.h"

#include "yacl/base/byte_container_view.h"
#include "yacl/math/common.h"
#include "yacl/utils/spi/type_traits.h"

namespace yacl::math::openssl {
using UniqueBnCtxPtr = std::unique_ptr<BN_CTX, std::function<void(BN_CTX*)>>;

using UniqueBnMontCtxPtr =
    std::unique_ptr<BN_MONT_CTX, std::function<void(BN_MONT_CTX*)>>;

class BigNum {
  using UniqueBnPtr = std::unique_ptr<BIGNUM, std::function<void(BIGNUM*)>>;

 public:
  BigNum();
  template <typename T, typename = std::enable_if_t<std::is_arithmetic_v<T>>>
  explicit BigNum(T value) {
    bn_ = {BN_new(), BN_free};
    Set(value);
  }
  BigNum(const std::string& str, int base);
  BigNum(const BigNum& other);
  BigNum(BigNum&& other) noexcept;
  BigNum& operator=(const BigNum& other);
  BigNum& operator=(BigNum&& other) noexcept;

  template <typename T, typename = std::enable_if_t<std::is_arithmetic_v<T>>>
  BigNum& operator=(T value) {
    Set(value);
    return *this;
  }

  void Set(const std::string& num, int radix);

  // T could be (u)int8/16/32/64/128
  template <typename T>
  void Set(T value) {
    if constexpr (std::is_signed_v<T>) {
      BN_signed_native2bn(reinterpret_cast<unsigned char*>(&value), sizeof(T),
                          bn_.get());
    } else {
      BN_native2bn(reinterpret_cast<unsigned char*>(&value), sizeof(T),
                   bn_.get());
    }
  }

  // T could be (u)int8/16/32/64/128
  template <typename T>
  [[nodiscard]] T Get() const {
    static_assert(Endian::native == Endian::little);
    auto num_bytes =
        std::max(BN_num_bytes(bn_.get()), static_cast<int>(sizeof(T)));
    std::vector<unsigned char> buf(num_bytes, 0);
    BN_bn2nativepad(bn_.get(), buf.data(), num_bytes);
    auto n = *reinterpret_cast<std::make_unsigned_t<T>*>(buf.data());
    if constexpr (std::is_signed_v<T>) {
      return IsNegative() ? -static_cast<T>(n) : static_cast<T>(n);
    } else {
      return n;
    }
  }

  BigNum& operator+=(const BigNum& other);
  BigNum& operator-=(const BigNum& other);
  BigNum& operator*=(const BigNum& other);
  BigNum& operator/=(const BigNum& other);
  BigNum& operator%=(const BigNum& mod);

  BigNum& operator+=(uint64_t value);
  BigNum& operator-=(uint64_t value);
  BigNum& operator*=(uint64_t value);
  BigNum& operator/=(uint64_t value);

  BigNum& operator&=(const BigNum& other);
  BigNum& operator|=(const BigNum& other);
  BigNum& operator^=(const BigNum& other);

  BigNum& operator<<=(size_t shift);
  BigNum& operator>>=(size_t shift);

  BigNum& operator++();
  BigNum operator++(int);
  BigNum& operator--();
  BigNum operator--(int);

  [[nodiscard]] BigNum operator-() const;
  void NegateInplace();

  [[nodiscard]] BigNum Pow(uint32_t e) const;
  void PowInplace(uint32_t e);

  [[nodiscard]] bool IsNegative() const;

  [[nodiscard]] bool IsZero() const;

  [[nodiscard]] bool IsOdd() const;

  [[nodiscard]] bool IsPrime() const;

  [[nodiscard]] size_t BitCount() const;

  [[nodiscard]] BigNum Abs() const;

  [[nodiscard]] int CompareAbs(const BigNum& other) const;
  [[nodiscard]] int CompareAbs(int64_t other) const;

  [[nodiscard]] BigNum AddMod(const BigNum& other, const BigNum& mod) const;
  [[nodiscard]] BigNum SubMod(const BigNum& other, const BigNum& mod) const;
  [[nodiscard]] BigNum MulMod(const BigNum& other, const BigNum& mod) const;
  [[nodiscard]] BigNum InvMod(const BigNum& mod) const;
  [[nodiscard]] BigNum PowMod(const BigNum& other, const BigNum& mod) const;

  [[nodiscard]] static BigNum Lcm(const BigNum& a, const BigNum& b);
  [[nodiscard]] static BigNum Gcd(const BigNum& a, const BigNum& b);

  // Select a random r in [0, n)
  [[nodiscard]] static BigNum RandomLtN(const BigNum& n);

  [[nodiscard]] static BigNum RandomExactBits(size_t bit_size);
  [[nodiscard]] static BigNum RandomMonicExactBits(size_t bit_size);

  [[nodiscard]] static BigNum RandPrimeOver(
      size_t bit_size, PrimeType prime_type = PrimeType::BBS);

  [[nodiscard]] static UniqueBnMontCtxPtr SetMontgomeryCtx(const BigNum& mod);

  BigNum& ToMontgomery(const UniqueBnMontCtxPtr& mont_ctx);
  BigNum& FromMontgomery(const UniqueBnMontCtxPtr& mont_ctx);

  [[nodiscard]] static BigNum MulModMontgomery(
      const BigNum& a, const BigNum& b, const UniqueBnMontCtxPtr& mont_ctx);

  [[nodiscard]] static BigNum PowModMontgomery(
      const BigNum& a, const BigNum& b, const BigNum& mod,
      const UniqueBnMontCtxPtr& mont_ctx);

  [[nodiscard]] uint8_t GetBit(size_t idx) const;
  void SetBit(size_t idx, uint8_t bit);

  [[nodiscard]] yacl::Buffer Serialize() const;

  // Serialize BigNum to already allocated buffer.
  // If buf is nullptr, then calc serialize size only
  // @return: the actual size of serialized buffer
  // @throw: if buf_len is too small, an exception will be thrown
  size_t Serialize(uint8_t* buf, size_t buf_len) const;

  void Deserialize(yacl::ByteContainerView buffer);

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

 private:
  [[nodiscard]] size_t SerializeSize() const;

  static thread_local UniqueBnCtxPtr bn_ctx_;
  UniqueBnPtr bn_;

  friend class OpensslMontSpace;
  friend BigNum operator+(const BigNum& lhs, const BigNum& rhs);
  friend BigNum operator-(const BigNum& lhs, const BigNum& rhs);
  friend BigNum operator*(const BigNum& lhs, const BigNum& rhs);
  friend BigNum operator/(const BigNum& lhs, const BigNum& rhs);
  friend BigNum operator%(const BigNum& lhs, const BigNum& rhs);

  friend BigNum operator+(const BigNum& lhs, uint64_t rhs);
  friend BigNum operator-(const BigNum& lhs, uint64_t rhs);
  friend BigNum operator*(const BigNum& lhs, uint64_t rhs);
  friend BigNum operator/(const BigNum& lhs, uint64_t rhs);
  friend uint64_t operator%(const BigNum& lhs, uint64_t rhs);

  friend BigNum operator&(const BigNum& lhs, const BigNum& rhs);
  friend BigNum operator|(const BigNum& lhs, const BigNum& rhs);
  friend BigNum operator^(const BigNum& lhs, const BigNum& rhs);

  friend bool operator>(const BigNum& lhs, const BigNum& rhs);
  friend bool operator<(const BigNum& lhs, const BigNum& rhs);
  friend bool operator>=(const BigNum& lhs, const BigNum& rhs);
  friend bool operator<=(const BigNum& lhs, const BigNum& rhs);
  friend bool operator==(const BigNum& lhs, const BigNum& rhs);
  friend bool operator!=(const BigNum& lhs, const BigNum& rhs);

  friend bool operator>(const BigNum& lhs, int64_t rhs);
  friend bool operator<(const BigNum& lhs, int64_t rhs);
  friend bool operator>=(const BigNum& lhs, int64_t rhs);
  friend bool operator<=(const BigNum& lhs, int64_t rhs);
  friend bool operator==(const BigNum& lhs, int64_t rhs);
  friend bool operator!=(const BigNum& lhs, int64_t rhs);

  friend BigNum operator<<(const BigNum& lhs, size_t rhs);
  friend BigNum operator>>(const BigNum& lhs, size_t rhs);

  template <typename FloatType>
  void SetFloatingPoint(FloatType value);

  template <typename FloatType>
  FloatType GetFloatingPoint() const;
};

template <>
void BigNum::Set(double value);

template <>
void BigNum::Set(float value);

template <>
double BigNum::Get<double>() const;

template <>
float BigNum::Get<float>() const;

}  // namespace yacl::math::openssl

template <>
struct std::hash<yacl::math::openssl::BigNum> {
  size_t operator()(const yacl::math::openssl::BigNum& x) const {
    return std::hash<std::string>{}(x.ToString());
  }
};
