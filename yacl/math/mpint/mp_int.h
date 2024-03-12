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

#pragma once

#include <memory>
#include <ostream>
#include <string>

#include "libtommath/tommath.h"
#include "msgpack.hpp"

#include "yacl/base/byte_container_view.h"
#include "yacl/base/int128.h"
#include "yacl/math/mpint/mp_int_enforce.h"
#include "yacl/math/mpint/tommath_ext_features.h"

namespace yacl::math {

enum class PrimeType : int {
  Normal = 0,    // p is prime
  BBS = 1,       // p = 3 mod 4
  Safe = 2,      // (p-1)/2 is prime, use FastSafe instead
  FastSafe = 8,  // (p-1)/2 is prime
};

/**
 * MPInt -- Multiple Precision Integer
 */
class MPInt {
 public:
  // Pre-defined variables ...
  // WARNING: Do not use these variables in the global environment. Your global
  // variables may be initialized earlier than these.
  static const MPInt _0_;
  static const MPInt _1_;
  static const MPInt _2_;

  //================================//
  //          Constructors          //
  //================================//

  MPInt();

  // Supported T = (u)int8/16/32/64/128 or float/double
  template <typename T, typename = std::enable_if_t<std::is_arithmetic_v<T>>>
  explicit MPInt(T value, size_t reserved_bits = sizeof(T) * CHAR_BIT) {
    // if T = double, the size is still safe because Set(double) will auto grow
    // memory
    auto digits =
        (std::max(reserved_bits, sizeof(T) * CHAR_BIT) + MP_DIGIT_BIT - 1) /
        MP_DIGIT_BIT;
    MPINT_ENFORCE_OK(mp_init_size(&n_, digits));
    Set(value);
  }

  // if radix == 0, the real radix will be auto-detected:
  //  - if num is started with 0x, the radix is 16
  //  - if num is started with 0, the radix is 8
  //  - otherwise radix is 10
  // Plus and minus signs are supported, e.g. MPInt("-0xFF") is -255
  explicit MPInt(const std::string &num, size_t radix = 0);

  MPInt(MPInt &&other) noexcept;
  MPInt(const MPInt &other);

  MPInt &operator=(const MPInt &other);
  MPInt &operator=(MPInt &&other) noexcept;  // not thread safe

  ~MPInt() { mp_clear(&n_); }

  //================================//
  //      Getters and setters       //
  //================================//

  template <typename T>
  [[nodiscard]] T Get() const;

  template <typename T>
  void Set(T value);

  // if radix <= 0, the real radix will be auto-detected:
  //  - if num is start with 0x, the radix is 16
  //  - if num is start with 0 , the radix is 8
  //  - otherwise radix is 10
  // Plus and minus signs are supported, e.g. "-0xFF" is -255
  void Set(const std::string &num, int radix = 0);

  void SetZero();
  [[nodiscard]] bool IsZero() const { return mp_iszero(&n_); }
  [[nodiscard]] bool IsOne() const { return mp_isone(&n_); }
  [[nodiscard]] bool IsNegative() const { return mp_isneg(&n_); }
  // is natural number (>= 0)
  [[nodiscard]] bool IsNatural() const { return !mp_isneg(&n_); }
  [[nodiscard]] bool IsPositive() const {
    return !mp_iszero(&n_) && !mp_isneg(&n_);
  }

  [[nodiscard]] bool IsOdd() const { return mp_isodd(&n_); }
  [[nodiscard]] bool IsEven() const { return mp_iseven(&n_); }

  // Get the i'th bit. Always return 0 or 1
  uint8_t operator[](int idx) const;
  uint8_t GetBit(int idx) const;
  void SetBit(int idx, uint8_t bit);

  [[nodiscard]] size_t BitCount() const;

  // The size of memory allocated by this MPInt.
  // Not equal to the byte size of the number, nor equal to the serialized size
  size_t SizeAllocated() { return n_.alloc * sizeof(mp_digit); }
  // The size of memory used by this MPInt.
  // Not equal to the byte size of the number, nor equal to the serialized size
  size_t SizeUsed() { return n_.used * sizeof(mp_digit); }

  //================================//
  //             Hashing            //
  //================================//

  friend struct std::hash<yacl::math::MPInt>;

  //================================//
  //          Comparators           //
  //================================//

  bool operator>(const MPInt &other) const;
  bool operator<(const MPInt &other) const;
  bool operator>=(const MPInt &other) const;
  bool operator<=(const MPInt &other) const;
  bool operator==(const MPInt &other) const;
  bool operator!=(const MPInt &other) const;

  // compare a to b
  // Returns:
  //  > 0:  this > other
  //  == 0: this == other
  //  < 0:  this < other
  [[nodiscard]] int Compare(const MPInt &other) const;

  // compare a to b
  // Returns:
  //  > 0:  |this| > |other|
  //  == 0: |this| == |other|
  //  < 0:  |this| < |other|
  [[nodiscard]] int CompareAbs(const MPInt &other) const;

  //================================//
  //           Operators            //
  //================================//

  MPInt operator+(const MPInt &operand2) const;
  MPInt operator-(const MPInt &operand2) const;
  MPInt operator*(const MPInt &operand2) const;
  MPInt operator/(const MPInt &operand2) const;
  MPInt operator%(const MPInt &operand2) const;
  MPInt operator<<(size_t operand2) const;
  MPInt operator>>(size_t operand2) const;
  MPInt operator-() const;
  MPInt operator&(const MPInt &operand2) const;
  MPInt operator|(const MPInt &operand2) const;
  MPInt operator^(const MPInt &operand2) const;

  MPInt operator+=(const MPInt &operand2);
  MPInt operator-=(const MPInt &operand2);
  MPInt operator*=(const MPInt &operand2);
  MPInt operator/=(const MPInt &operand2);
  MPInt operator%=(const MPInt &operand2);
  MPInt operator<<=(size_t operand2);
  MPInt operator>>=(size_t operand2);
  MPInt operator&=(const MPInt &operand2);
  MPInt operator|=(const MPInt &operand2);
  MPInt operator^=(const MPInt &operand2);

  MPInt &DecrOne() &;
  MPInt &IncrOne() &;
  [[nodiscard]] MPInt &&DecrOne() &&;
  [[nodiscard]] MPInt &&IncrOne() &&;

  [[nodiscard]] MPInt Abs() const;

  // (*c) = a + b
  static void Add(const MPInt &a, const MPInt &b, MPInt *c);

  MPInt AddMod(const MPInt &b, const MPInt &mod) const;
  static void AddMod(const MPInt &a, const MPInt &b, const MPInt &mod,
                     MPInt *d);

  // (*c) = a - b
  static void Sub(const MPInt &a, const MPInt &b, MPInt *c);

  MPInt SubMod(const MPInt &b, const MPInt &mod) const;
  static void SubMod(const MPInt &a, const MPInt &b, const MPInt &mod,
                     MPInt *d);

  // (*c) = a * b
  static void Mul(const MPInt &a, const MPInt &b, MPInt *c);
  MPInt Mul(mp_digit b) const;
  void MulInplace(mp_digit b);

  MPInt MulMod(const MPInt &b, const MPInt &mod) const;
  static void MulMod(const MPInt &a, const MPInt &b, const MPInt &mod,
                     MPInt *d);

  // *d = (a**b) mod c
  static void Pow(const MPInt &a, uint32_t b, MPInt *c);
  MPInt Pow(uint32_t b) const;
  void PowInplace(uint32_t b);

  static void PowMod(const MPInt &a, const MPInt &b, const MPInt &mod,
                     MPInt *d);
  MPInt PowMod(const MPInt &b, const MPInt &mod) const;

  /* a/b => cb + d == a */
  static void Div(const MPInt &a, const MPInt &b, MPInt *c, MPInt *d);

  // b = a // 3
  static void Div3(const MPInt &a, MPInt *b);

  // ac = 1 (mod b)
  // example: a = 3, b = 10000, output c = 6667
  //
  // note:
  // A necessary and sufficient condition for the existence of c is that a
  // and b are coprime. If a and b are not coprime, then c does not exist and an
  // exception is thrown
  static void InvertMod(const MPInt &a, const MPInt &mod, MPInt *c);
  MPInt InvertMod(const MPInt &mod) const;

  /* c = a mod b, 0 <= c < b  */
  static void Mod(const MPInt &a, const MPInt &mod, MPInt *c);
  MPInt Mod(const MPInt &mod) const;

  /* a = -a */
  inline void Negate(MPInt *z) const { MPINT_ENFORCE_OK(mp_neg(&n_, &z->n_)); }
  inline void NegateInplace() { MPINT_ENFORCE_OK(mp_neg(&n_, &n_)); }

  /**
   * Generate a random number >= 0
   * @note
   * The random number generated by libtommath is a multiple of
   * MP_DIGIT_BIT(=60) bit.
   *
   * For example, if the input bit_size = 105, then:
   * > RandomRoundDown
   *     - Generate a 60-bit random number with the highest bit being 1.
   * > RandomRoundUp
   *     - Generate 120-bit random numbers with the highest bit being 1.
   * > RandomExactBits
   *     - Generate an exact bit_size random number, the msb is not guaranteed
   * to be 1.
   * > RandomMonicExactBits
   *     - Generate an exact bit_size random number with the highest bit
   * being 1.
   */
  static void RandomRoundDown(size_t bit_size, MPInt *r);
  static void RandomRoundUp(size_t bit_size, MPInt *r);
  static void RandomExactBits(size_t bit_size, MPInt *r);
  static void RandomMonicExactBits(size_t bit_size, MPInt *r);

  // select a random r in [0, n)
  static void RandomLtN(const MPInt &n, MPInt *r);

  static void Lcm(const MPInt &a, const MPInt &b, MPInt *c);
  static void Gcd(const MPInt &a, const MPInt &b, MPInt *c);

  //================================//
  //          Prime tools           //
  //================================//

  [[nodiscard]] bool IsPrime() const;

  /**
   * Generate a random prime
   * *Warning*: You can NOT call this function before main() function
   * +------------+--------------+-----------------+
   * |            |  bit length  |   average time  |
   * +------------+--------------+-----------------+
   * |            |     1024     |       1 min     |
   * | safe prime |--------------+-----------------+
   * |            |     2048     |      30 min     |
   * +------------+--------------+-----------------+
   * |   fast     |     1024     |      20 sec     |
   * |   safe     |--------------+-----------------+
   * |   prime    |     2048     |       1 min     |
   * +------------+--------------+-----------------+
   * You can rerun the benchmark using following command:
   *    bazel run -c opt heu/library/phe/benchmark:mpint
   * @param[in] bit_size prime bit size, at least 81 bits
   * @param[out] out a bit_size prime whose highest bit always one
   */
  static void RandPrimeOver(size_t bit_size, MPInt *out,
                            PrimeType prime_type = PrimeType::BBS);

  //================================//
  //               I/O              //
  //================================//

  friend std::ostream &operator<<(std::ostream &os, const MPInt &an_int);

  [[nodiscard]] yacl::Buffer Serialize() const;
  // serialize mpint to already allocated buffer.
  // if buf is nullptr, then calc serialize size only
  // @return: the actual size of serialized buffer
  // @throw: if buf_len is too small, an exception will be thrown
  size_t Serialize(uint8_t *buf, size_t buf_len) const;

  void Deserialize(yacl::ByteContainerView buffer);
  [[nodiscard]] std::string ToString() const;
  [[nodiscard]] std::string ToHexString() const;

  // Convert MPInt to a two's complement byte string.
  // If byte_len is too small, the value will be truncated.
  // If byte_len exceeds the actual size, the high bits of the buffer will be
  // filled with 0 for positive number, otherwise 1.
  yacl::Buffer ToBytes(size_t byte_len, Endian endian = Endian::native) const;
  void ToBytes(unsigned char *buf, size_t buf_len,
               Endian endian = Endian::native) const;

  // Converts the absolute value of MPInt into a byte string.
  // Equals: this->Abs().ToBytes((this->BitCount() + 7) / 8, endian)
  yacl::Buffer ToMagBytes(Endian endian = Endian::native) const;
  // If buf_len is too small, an exception will be thrown.
  // If buf_len exceeds the actual required size, considering the
  // characteristics of big-endian, the remaining part will not be assigned 0.
  // If buf is nullptr, then calc serialize size only
  // @return: the number of bytes written
  size_t ToMagBytes(unsigned char *buf, size_t buf_len,
                    Endian endian = Endian::native) const;

  // Converts the positive integer in buffer to a (positive) MPInt.
  // The previous value and sign in MPInt will be overwritten
  void FromMagBytes(yacl::ByteContainerView buffer,
                    Endian endian = Endian::native);

  //================================//
  //    Other advanced functions    //
  //================================//

  // if combiner is add, output scalar * base
  // if combiner is mul, output base ** scalar
  // warning: this function is very slow.
  template <typename T>
  static T SlowCustomPow(
      const T &identity, const T &base, const MPInt &scalar,
      const std::function<void(T *, const T &)> &combine_inplace) {
    YACL_ENFORCE(!scalar.IsNegative(), "scalar must >= 0, get {}", scalar);

    if (scalar.IsZero()) {
      return identity;
    }

    T res = identity;
    T s = base;
    for (int digit_idx = 0; digit_idx < scalar.n_.used - 1; ++digit_idx) {
      mp_digit e = scalar.n_.dp[digit_idx];
      for (int i = 0; i < MP_DIGIT_BIT; ++i) {
        if (e & 1) {
          combine_inplace(&res, s);
        }
        e >>= 1;
        combine_inplace(&s, s);
      }
    }

    // process last digit
    mp_digit e = scalar.n_.dp[scalar.n_.used - 1] & MP_MASK;
    while (e != 0) {
      if (e & 1) {
        combine_inplace(&res, s);
      }
      e >>= 1;
      if (e != 0) {
        combine_inplace(&s, s);
      }
    }
    return res;
  }

 protected:
  mp_int n_;

 private:
  [[nodiscard]] std::string ToRadixString(int radix) const;

  friend class MontgomerySpace;
};

// for fmtlib
inline auto format_as(const MPInt &i) { return fmt::streamed(i); }

}  // namespace yacl::math

yacl::math::MPInt operator""_mp(const char *sz, size_t n);
yacl::math::MPInt operator""_mp(unsigned long long num);

template <>
struct std::hash<yacl::math::MPInt> {
  size_t operator()(const yacl::math::MPInt &x) const {
    uint64_t h;
    MPINT_ENFORCE_OK(mp_hash(&x.n_, &h));
    return h;
  }
};

namespace msgpack {
MSGPACK_API_VERSION_NAMESPACE(MSGPACK_DEFAULT_API_NS) {
  namespace adaptor {

  template <>
  struct pack<yacl::math::MPInt> {
    template <typename Stream>
    msgpack::packer<Stream> &operator()(msgpack::packer<Stream> &object,
                                        const yacl::math::MPInt &mp) const {
      object.pack(std::string_view(mp.Serialize()));
      return object;
    }
  };

  template <>
  struct convert<yacl::math::MPInt> {
    const msgpack::object &operator()(const msgpack::object &object,
                                      yacl::math::MPInt &mp) const {
      mp.Deserialize(object.as<std::string_view>());
      return object;
    }
  };

  }  // namespace adaptor
}  // MSGPACK_API_VERSION_NAMESPACE(MSGPACK_DEFAULT_API_NS)
}  // namespace msgpack
