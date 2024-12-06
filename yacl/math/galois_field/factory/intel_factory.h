// Copyright 2023 Ant Group Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

#include <array>
#include <cstdint>
#include <type_traits>

#include "yacl/base/exception.h"
#include "yacl/base/int128.h"
#include "yacl/crypto/rand/rand.h"
#include "yacl/math/galois_field/factory/gf_scalar.h"

namespace yacl::math {

// Galois Field GF(2^n) implmentation
//
// Currently intrinsic field only supports F_{2^64} and F_{2^128}. Therefore
// this class only takes input type as uint64_t or uint128_t.
template <typename T,
          std::enable_if_t<std::disjunction<std::is_same<T, uint128_t>,
                                            std::is_same<T, uint64_t>>::value,
                           bool> = true>
class IntrinsicField : public GFScalarSketch<T> {
 public:
  std::string GetLibraryName() const override { return kIntelLib; }
  std::string GetFieldName() const override { return kBinaryField; }

  MPInt GetOrder() const override {
    MPInt ret = 2_mp;
    ret.PowInplace(sizeof(T) * 8);
    return ret;
  }

  MPInt GetMulGroupOrder() const override { return GetOrder(); }
  MPInt GetAddGroupOrder() const override { return GetOrder(); }
  uint64_t GetExtensionDegree() const override { return sizeof(T) * 8; }
  MPInt GetBaseFieldOrder() const override { return MPInt(2); }

  Item GetIdentityZero() const override { return T(0); }
  Item GetIdentityOne() const override { return T(1); }

  bool IsIdentityOne(const T& x) const override { return x == 1; }
  bool IsIdentityZero(const T& x) const override { return x == 0; }
  bool IsInField([[maybe_unused]] const T& x) const override { return true; }

  bool Equal(const T& x, const T& y) const override { return x == y; }

  //==================================//
  //   operations defined on field    //
  //==================================//

  // get the additive inverse −a for all elements in set
  T Neg(const T& x) const override { return x; }
  void NegInplace([[maybe_unused]] T* x) const override {}

  // get the multiplicative inverse 1/b for every nonzero element in set
  T Inv(const T& x) const override;
  void InvInplace(T* x) const override { *x = Inv(*x); }

  T Add(const T& x, const T& y) const override { return x ^ y; }
  void AddInplace(T* x, const T& y) const override { *x = Add(*x, y); }

  T Sub(const T& x, const T& y) const override { return x ^ y; }
  void SubInplace(T* x, const T& y) const override { *x = Sub(*x, y); }

  T Mul(const T& x, const T& y) const override;
  void MulInplace(T* x, const T& y) const override { *x = Mul(*x, y); }

  T Div(const T& x, const T& y) const override { return Mul(x, Inv(y)); }
  void DivInplace(T* x, const T& y) const override { *x = Div(*x, y); }

  T Pow(const T& x, const MPInt& y) const override;
  void PowInplace(T* x, const MPInt& y) const override { *x = Pow(*x, y); }

  // scalar version: return a random scalar element
  T RandomT() const override {
    T ret;
    crypto::FillRand((char*)&ret, sizeof(T));
    return ret;
  }

  //==================================//
  //   operations defined on field    //
  //==================================//

  T DeepCopy(const T& x) const override { return x; }

  // To human-readable string
  std::string ToString(const T& x) const override {
    return fmt::format("{}", x);
  }

  size_t Serialize(const T& x, uint8_t* buf, size_t buf_len) const override {
    YACL_ENFORCE(sizeof(T) == buf_len);
    memcpy(buf, &x, buf_len);
    return buf_len;
  }

  T DeserializeT(ByteContainerView buffer) const override {
    YACL_ENFORCE(sizeof(T) == buffer.size());
    T ret;
    memcpy(&ret, buffer.data(), buffer.size());
    return ret;
  }

  // compile-time utilities for generating galois field basis for uint64_t and
  // uint128_t
  constexpr std::array<T, sizeof(T) * 8> GenGfBasisArray() {
    std::array<T, sizeof(T) * 8> basis = {0};
    uint128_t one = yacl::MakeUint128(0, 1);
    for (size_t i = 0; i < sizeof(T) * 8; ++i) {
      basis[i] = one << i;
    }
    return basis;
  }
};

// -----------------------
// Register this lib
// -----------------------
class IntrinsicFieldFactory {
 public:
  static std::unique_ptr<GaloisField> Create(const std::string& field_name,
                                             const SpiArgs& args);
  static bool Check(const std::string& field_name, const SpiArgs&);
};

}  // namespace yacl::math
