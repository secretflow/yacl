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

#include <string>
#include <type_traits>

#include "yacl/base/byte_container_view.h"
#include "yacl/math/bigint/gmp/gmp_loader.h"
#include "yacl/math/common.h"
#include "yacl/utils/spi/type_traits.h"

namespace yacl::math::gmp {

class GMPLoader;
class GMPInt {
 public:
  GMPInt();
  explicit GMPInt(const std::string& str, int base);

  template <typename T, typename = std::enable_if_t<std::is_arithmetic_v<T>>>
  explicit GMPInt(T value, size_t reserved_bits = 0) {
    YACL_ENFORCE(gmp_.IsLoaded(), "GMP is not loaded");
    if (reserved_bits > 0) {
      // In preparation for an operation, GMP often allocates one limb more than
      // ultimately needed
      gmp_.mpz_init2_(z_, reserved_bits + GMP_LIMB_BITS);
    } else {
      gmp_.mpz_init_(z_);
    }
    if (value != 0) {
      Set(value);
    }
  }

  GMPInt(const GMPInt&);
  GMPInt(GMPInt&&) noexcept;
  GMPInt& operator=(const GMPInt&);
  GMPInt& operator=(GMPInt&&) noexcept;

  template <typename T, typename = std::enable_if_t<std::is_arithmetic_v<T>>>
  GMPInt& operator=(T value) {
    Set(value);
    return *this;
  }

  ~GMPInt();

  void Set(const std::string& num, int radix);

  // T could be (u)int8/16/32/64/128 or float/double
  template <typename T>
  void Set(T value) {
    if constexpr (std::is_floating_point_v<T>) {
      gmp_.mpz_set_d_(z_, value);
    } else if constexpr (sizeof(T) <= sizeof(unsigned long)) {
      if constexpr (std::is_signed_v<T>) {
        gmp_.mpz_set_si_(z_, value);
      } else {
        gmp_.mpz_set_ui_(z_, value);
      }
    } else {
      if (value < 0) {
        auto v = -static_cast<std::make_unsigned_t<T>>(value);
        gmp_.mpz_import_(z_, 1, 0, sizeof(T), 0, 0, &v);
        gmp_.mpz_neg_(z_, z_);
      } else {
        gmp_.mpz_import_(z_, 1, 0, sizeof(T), 0, 0, &value);
      }
    }
  }

  // T could be (u)int8/16/32/64/128 or float/double
  template <typename T>
  [[nodiscard]] T Get() const {
    if constexpr (std::is_floating_point_v<T>) {
      return gmp_.mpz_get_d_(z_);
    } else {
      std::make_unsigned_t<T> n;
      if constexpr (sizeof(T) <= sizeof(unsigned long)) {
        n = gmp_.mpz_get_ui_(z_);
      } else {
        static_assert(Endian::native == Endian::little);
        size_t num_bytes =
            std::max((gmp_.mpz_sizeinbase_(z_, 2) + 7) / 8, sizeof(T));
        std::vector<unsigned char> buf(num_bytes, 0);
        gmp_.mpz_export_(buf.data(), nullptr, -1, 1, 0, 0, z_);
        n = *reinterpret_cast<std::make_unsigned_t<T>*>(buf.data());
      }

      if constexpr (std::is_signed_v<T>) {
        return IsNegative() ? -static_cast<T>(n) : static_cast<T>(n);
      } else {
        return n;
      }
    }
  }

  GMPInt& operator+=(const GMPInt& n);
  GMPInt& operator-=(const GMPInt& n);
  GMPInt& operator*=(const GMPInt& n);
  GMPInt& operator/=(const GMPInt& n);
  GMPInt& operator%=(const GMPInt& mod);

  GMPInt& operator+=(uint64_t n);
  GMPInt& operator-=(uint64_t n);
  GMPInt& operator*=(uint64_t n);
  GMPInt& operator/=(uint64_t n);

  GMPInt& operator&=(const GMPInt& n);
  GMPInt& operator|=(const GMPInt& n);
  GMPInt& operator^=(const GMPInt& n);

  GMPInt& operator<<=(mp_bitcnt_t bit_cnt);
  GMPInt& operator>>=(mp_bitcnt_t bit_cnt);

  GMPInt& operator++();
  GMPInt operator++(int);
  GMPInt& operator--();
  GMPInt operator--(int);

  [[nodiscard]] GMPInt operator-() const;

  [[nodiscard]] GMPInt operator<<(mp_bitcnt_t bit_cnt) const;
  [[nodiscard]] GMPInt operator>>(mp_bitcnt_t bit_cnt) const;

  void NegateInplace();

  [[nodiscard]] GMPInt Pow(uint32_t e) const;
  void PowInplace(uint32_t e);

  [[nodiscard]] bool IsNegative() const;

  [[nodiscard]] bool IsZero() const;

  [[nodiscard]] bool IsOdd() const;

  [[nodiscard]] bool IsPrime() const;

  [[nodiscard]] size_t BitCount() const;

  [[nodiscard]] GMPInt Abs() const;

  [[nodiscard]] int CompareAbs(const GMPInt& other) const;
  [[nodiscard]] int CompareAbs(int64_t other) const;

  [[nodiscard]] GMPInt AddMod(const GMPInt& other, const GMPInt& mod) const;
  [[nodiscard]] GMPInt SubMod(const GMPInt& other, const GMPInt& mod) const;
  [[nodiscard]] GMPInt MulMod(const GMPInt& other, const GMPInt& mod) const;
  [[nodiscard]] GMPInt InvMod(const GMPInt& mod) const;
  [[nodiscard]] GMPInt PowMod(const GMPInt& other, const GMPInt& mod) const;

  [[nodiscard]] static GMPInt Lcm(const GMPInt& a, const GMPInt& b);
  [[nodiscard]] static GMPInt Gcd(const GMPInt& a, const GMPInt& b);

  [[nodiscard]] static GMPInt RandomExactBits(size_t bit_size);
  [[nodiscard]] static GMPInt RandomMonicExactBits(size_t bit_size);

  // Select a random r in [0, n)
  [[nodiscard]] static GMPInt RandomLtN(const GMPInt& n);

  [[nodiscard]] static GMPInt RandPrimeOver(
      mp_bitcnt_t bit_size, PrimeType prime_type = PrimeType::BBS);

  [[nodiscard]] static mp_limb_t MontgomerySetup(const GMPInt& mod);

  [[nodiscard]] static GMPInt MontgomeryCalcNormalization(const GMPInt& mod);

  // Computes x/R == x (mod N) via Montgomery Reduction
  GMPInt& MontgomeryReduce(const GMPInt& mod, mp_limb_t rho);

  [[nodiscard]] uint8_t GetBit(size_t idx) const;
  void SetBit(size_t idx, uint8_t bit);

  [[nodiscard]] yacl::Buffer Serialize() const;

  // Serialize GMPInt to already allocated buffer.
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
  GMPInt& MontgomeryReduceComba(const GMPInt& mod, mp_limb_t rho);

  [[nodiscard]] size_t SerializeSize() const;

  const GMPLoader& gmp_ = GMPLoader::Instance();
  mpz_t z_;

  class RandState {
   public:
    RandState() { GMPLoader::Instance().gmp_randinit_default_(state_); }
    ~RandState() { GMPLoader::Instance().gmp_randclear_(state_); }

    RandState(const RandState&) = delete;
    RandState& operator=(const RandState&) = delete;
    RandState(RandState&&) = delete;
    RandState& operator=(RandState&&) = delete;

    [[nodiscard]] gmp_randstate_t& Get() { return state_; }

   private:
    gmp_randstate_t state_;
  };

  thread_local static RandState rand_state_;

  friend class GmpMontSpace;
  friend GMPInt operator+(const GMPInt& lhs, const GMPInt& rhs);
  friend GMPInt operator-(const GMPInt& lhs, const GMPInt& rhs);
  friend GMPInt operator*(const GMPInt& lhs, const GMPInt& rhs);
  friend GMPInt operator/(const GMPInt& lhs, const GMPInt& rhs);
  friend GMPInt operator%(const GMPInt& lhs, const GMPInt& rhs);

  friend GMPInt operator+(const GMPInt& lhs, uint64_t rhs);
  friend GMPInt operator-(const GMPInt& lhs, uint64_t rhs);
  friend GMPInt operator*(const GMPInt& lhs, uint64_t rhs);
  friend GMPInt operator/(const GMPInt& lhs, uint64_t rhs);
  friend uint64_t operator%(const GMPInt& lhs, uint64_t rhs);

  friend GMPInt operator&(const GMPInt& lhs, const GMPInt& rhs);
  friend GMPInt operator|(const GMPInt& lhs, const GMPInt& rhs);
  friend GMPInt operator^(const GMPInt& lhs, const GMPInt& rhs);

  friend bool operator>(const GMPInt& lhs, const GMPInt& rhs);
  friend bool operator<(const GMPInt& lhs, const GMPInt& rhs);
  friend bool operator>=(const GMPInt& lhs, const GMPInt& rhs);
  friend bool operator<=(const GMPInt& lhs, const GMPInt& rhs);
  friend bool operator==(const GMPInt& lhs, const GMPInt& rhs);
  friend bool operator!=(const GMPInt& lhs, const GMPInt& rhs);

  friend bool operator>(const GMPInt& lhs, int64_t rhs);
  friend bool operator<(const GMPInt& lhs, int64_t rhs);
  friend bool operator>=(const GMPInt& lhs, int64_t rhs);
  friend bool operator<=(const GMPInt& lhs, int64_t rhs);
  friend bool operator==(const GMPInt& lhs, int64_t rhs);
  friend bool operator!=(const GMPInt& lhs, int64_t rhs);
};

}  // namespace yacl::math::gmp

template <>
struct std::hash<yacl::math::gmp::GMPInt> {
  size_t operator()(const yacl::math::gmp::GMPInt& x) const {
    return std::hash<std::string>{}(x.ToString());
  }
};
