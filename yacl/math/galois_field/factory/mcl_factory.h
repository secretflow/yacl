// Copyright 2023 Ant Group Co., Ltd.
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

#include "mcl/fp.hpp"
#include "mcl/fp_tower.hpp"

#include "yacl/math/galois_field/factory/gf_scalar.h"

namespace yacl::math {

class MclFieldFactory {
 public:
  static std::unique_ptr<GaloisField> Create(const std::string& field_name,
                                             const SpiArgs& args);
  static bool Check(const std::string& field_name, const SpiArgs&);
};

enum Type {
  Normal,
  Add,
  Mul,
};

template <typename T, size_t degree>
class MclField : public GFScalarSketch<T> {
 private:
 public:
  using T_ = T;
  std::string GetLibraryName() const override;
  std::string GetFieldName() const override;

  MPInt GetOrder() const override;
  MPInt GetMulGroupOrder() const override;
  MPInt GetAddGroupOrder() const override;
  uint64_t GetExtensionDegree() const override;
  MPInt GetBaseFieldOrder() const override;

  Item GetIdentityZero() const override;
  Item GetIdentityOne() const override;

  bool IsIdentityOne(const T& x) const override;
  bool IsIdentityZero(const T& x) const override;
  bool IsInField(const T& x) const override;

  bool Equal(const T& x, const T& y) const override;

  //==================================//
  //   operations defined on field    //
  //==================================//

  // get the additive inverse −a for all elements in set
  T Neg(const T& x) const override;
  void NegInplace(T* x) const override;

  // get the multiplicative inverse 1/b for every nonzero element in set
  T Inv(const T& x) const override;
  void InvInplace(T* x) const override;

  T Add(const T& x, const T& y) const override;
  void AddInplace(T* x, const T& y) const override;

  T Sub(const T& x, const T& y) const override;
  void SubInplace(T* x, const T& y) const override;

  T Mul(const T& x, const T& y) const override;
  void MulInplace(T* x, const T& y) const override;

  T Div(const T& x, const T& y) const override;
  void DivInplace(T* x, const T& y) const override;

  T Pow(const T& x, const MPInt& y) const override;
  void PowInplace(T* x, const MPInt& y) const override;

  // scalar version: return a random scalar element
  T RandomT() const override;

  //==================================//
  //   operations defined on field    //
  //==================================//

  T DeepCopy(const T& x) const override;

  // To human-readable string
  std::string ToString(const T& x) const override;

  size_t Serialize(const T& x, uint8_t* buf, size_t buf_len) const override;

  T DeserializeT(ByteContainerView buffer) const override;

  explicit MclField(const MPInt& order, Type field_type);

 private:
  // xi_a is used for Fp2::mul_xi(), where xi = xi_a + i and i^2 = -1, see
  // Fp::init(int xi_a, ...)
  explicit MclField(const MPInt& base_prime_p,
                    mcl::fp::Mode mode = mcl::fp::FP_AUTO, int xi_a = 1);
  // Sometimes the order_ maybe used as the subgroup order over field
  // For additive group, given an element $e$ in field, $e * order_ = 0$,
  // For multiplicative group, given an element $e$ in field, $e^(order_-1)=1$.
  MPInt order_;
  MPInt order_mul_;
  MPInt order_add_;

  friend class MclFieldFactory;
};

using DefaultFp = mcl::FpT<>;                     // size 512
using FpWithSize256 = mcl::FpT<mcl::FpTag, 256>;  // Max element size 256 bits
using DefaultFp2 = mcl::Fp2T<mcl::FpT<>>;
using DefaultFp6 = mcl::Fp6T<mcl::FpT<>>;
using DefaultFp12 = mcl::Fp12T<mcl::FpT<>>;  // size 512

}  // namespace yacl::math
