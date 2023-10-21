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

#include <variant>

#include "yacl/base/block.h"
#include "yacl/crypto/base/ecc/any_ptr.h"
#include "yacl/math/mpint/mp_int.h"

namespace yacl::crypto {

using FElement = std::variant<AnyPtr, block>;
using yacl::math::MPInt;

// Finite Prime Field(FElement) and including its extension, i.e.,
// FElement2,FElement6,FElement12,FElement^n
class Field {
 public:
  virtual ~Field() = default;

  virtual std::string GetLibraryName() const = 0;
  virtual std::string GetFieldName() const = 0;
  virtual int64_t GetExtensionDegree() const = 0;
  // getBasePrimeP?

  // The order of Finite Field will always be k-th power of a prime number p and
  // in extension field, field order and field modulus are different and not
  // directly related, which is unlike in normal prime field that field order is
  // just field modulus.
  // Note, the origin order(p^k) of extension field(degree k>1) is actually
  // useless for field computation. So we usually disable `GetOrder` for
  // extension field and set it to be 0, except we are dealing within a subfield
  // from the upper extension field.
  virtual MPInt GetOrder() const = 0;

  virtual bool IsOne(const FElement& x) const = 0;
  virtual bool IsZero(const FElement& x) const = 0;
  virtual bool Equal(const FElement& x, const FElement& y) const = 0;

  virtual FElement Rand() const = 0;

  // univariate input
  virtual void SetOne(FElement* x) const = 0;
  virtual FElement MakeOne() const = 0;
  virtual void SetZero(FElement* x) const = 0;
  virtual FElement MakeZero() const = 0;
  virtual FElement MakeInstance() const = 0;
  virtual FElement FromInt64(int64_t i) const = 0;
  virtual FElement Copy(const FElement& x) const = 0;

  virtual FElement Neg(const FElement& x) const = 0;
  // virtual void NegInplace(FElement* x) const = 0;
  virtual FElement Sqr(const FElement& x) const = 0;
  // virtual void SqrInplace(FElement* x) const = 0;
  virtual FElement Inv(const FElement& x) const = 0;
  // virtual void InvInplace(FElement* x) const = 0;

  // bivariate inputs
  virtual FElement Add(const FElement& x, const FElement& y) const = 0;
  virtual void AddInplace(FElement* x, const FElement& y) const = 0;

  virtual FElement Sub(const FElement& x, const FElement& y) const = 0;
  virtual void SubInplace(FElement* x, const FElement& y) const = 0;

  virtual FElement Mul(const FElement& x, const FElement& y) const = 0;
  virtual void MulInplace(FElement* x, const FElement& y) const = 0;

  virtual FElement Div(const FElement& x, const FElement& y) const = 0;
  virtual void DivInplace(FElement* x, const FElement& y) const = 0;

  virtual FElement Pow(const FElement& x, const MPInt& y) const = 0;
  virtual void PowInplace(FElement* x, const MPInt& y) const = 0;

  // virtual FElement powVec(const FElement* x, const MPInt* y, uint64_t n)
  // const = 0;

  // serialize
  virtual std::string ToString(const FElement& x) const = 0;
  virtual FElement FromString(const std::string& x) const = 0;
  virtual std::string ToDecString(const FElement& x) const = 0;
  virtual FElement FromDecString(const std::string& x) const = 0;
  virtual std::string ToHexString(const FElement& x) const = 0;
  virtual FElement FromHexString(const std::string& x) const = 0;
  virtual Buffer Serialize(const FElement& x) const = 0;
  virtual FElement Deserialize(ByteContainerView buffer) const = 0;
};

}  // namespace yacl::crypto
