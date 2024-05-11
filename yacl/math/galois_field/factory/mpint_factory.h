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

#include <utility>

#include "yacl/math/galois_field/factory/gf_scalar.h"
#include "yacl/math/mpint/mp_int.h"

namespace yacl::math {

class MPIntField : public GFScalarSketch<MPInt> {
 public:
  static std::unique_ptr<GaloisField> Create(const std::string &field_name,
                                             const SpiArgs &args);
  static bool Check(const std::string &field_name, const SpiArgs &);
  ~MPIntField() override = default;

  std::string GetLibraryName() const override;
  std::string GetFieldName() const override;

  MPInt GetOrder() const override;
  MPInt GetMulGroupOrder() const override;
  MPInt GetAddGroupOrder() const override;
  uint64_t GetExtensionDegree() const override;
  MPInt GetBaseFieldOrder() const override;

  Item GetIdentityZero() const override;
  Item GetIdentityOne() const override;

  bool IsIdentityOne(const MPInt &x) const override;
  bool IsIdentityZero(const MPInt &x) const override;
  bool IsInField(const MPInt &x) const override;
  bool Equal(const MPInt &x, const MPInt &y) const override;

  //==================================//
  //   operations defined on field    //
  //==================================//

  MPInt Neg(const MPInt &x) const override;
  void NegInplace(MPInt *x) const override;
  MPInt Inv(const MPInt &x) const override;
  void InvInplace(MPInt *x) const override;

  MPInt Add(const MPInt &x, const MPInt &y) const override;
  void AddInplace(MPInt *x, const MPInt &y) const override;

  MPInt Sub(const MPInt &x, const MPInt &y) const override;
  void SubInplace(MPInt *x, const MPInt &y) const override;
  MPInt Mul(const MPInt &x, const MPInt &y) const override;
  void MulInplace(MPInt *x, const MPInt &y) const override;
  MPInt Div(const MPInt &x, const MPInt &y) const override;
  void DivInplace(MPInt *x, const MPInt &y) const override;
  MPInt Pow(const MPInt &x, const MPInt &y) const override;
  void PowInplace(MPInt *x, const MPInt &y) const override;

  MPInt RandomT() const override;

  MPInt DeepCopy(const MPInt &x) const override;
  std::string ToString(const MPInt &x) const override;

  size_t Serialize(const MPInt &x, uint8_t *buf, size_t buf_len) const override;
  MPInt DeserializeT(ByteContainerView buffer) const override;

 private:
  explicit MPIntField(MPInt mod) : mod_(std::move(mod)) {}

  MPInt mod_;
};

}  // namespace yacl::math
