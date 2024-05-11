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

#include "absl/types/span.h"

#include "yacl/math/galois_field/factory/gf_spi.h"

namespace yacl::math {

template <typename T>
class GFVectorizedSketch : public GaloisField {
 public:
  // if x is scalar, returns bool
  // if x is vectored, returns std::vector<bool>
  virtual std::vector<bool> IsIdentityOne(absl::Span<const T> x) const = 0;
  virtual std::vector<bool> IsIdentityZero(absl::Span<const T> x) const = 0;
  virtual std::vector<bool> IsInField(absl::Span<const T> x) const = 0;

  virtual bool Equal(absl::Span<const T> x, absl::Span<const T> y) const = 0;

  //================================//
  //   operations defined on set    //
  //================================//

  // get the additive inverse −a for all elements in set
  virtual std::vector<T> Neg(absl::Span<const T> x) const = 0;
  virtual void NegInplace(absl::Span<T> x) const = 0;

  // get the multiplicative inverse 1/b for every nonzero element in set
  virtual std::vector<T> Inv(absl::Span<const T> x) const = 0;
  virtual void InvInplace(absl::Span<T> x) const = 0;

  virtual std::vector<T> Add(absl::Span<const T> x,
                             absl::Span<const T> y) const = 0;
  virtual void AddInplace(absl::Span<T> x, absl::Span<const T> y) const = 0;

  virtual std::vector<T> Sub(absl::Span<const T> x,
                             absl::Span<const T> y) const = 0;
  virtual void SubInplace(absl::Span<T> x, absl::Span<const T> y) const = 0;

  virtual std::vector<T> Mul(absl::Span<const T> x,
                             absl::Span<const T> y) const = 0;
  virtual void MulInplace(absl::Span<T> x, absl::Span<const T> y) const = 0;

  virtual std::vector<T> Div(absl::Span<const T> x,
                             absl::Span<const T> y) const = 0;
  virtual void DivInplace(absl::Span<T> x, absl::Span<const T> y) const = 0;

  virtual std::vector<T> Pow(absl::Span<const T> x, const MPInt& y) const = 0;
  virtual void PowInplace(absl::Span<T> x, const MPInt& y) const = 0;

  virtual std::vector<T> RandomT(size_t count) const = 0;

  //================================//
  //              I/O               //
  //================================//

  virtual std::vector<T> DeepCopy(absl::Span<const T> x) const = 0;

  // To human-readable string
  virtual std::string ToString(absl::Span<const T> x) const = 0;

  virtual Buffer Serialize(absl::Span<const T> x) const = 0;
  // serialize field element(s) to already allocated buffer.
  // if buf is nullptr, then calc serialize size only
  // @return: the actual size of serialized buffer
  virtual size_t Serialize(absl::Span<const T> x, uint8_t* buf,
                           size_t buf_len) const = 0;

  virtual std::vector<T> DeserializeT(ByteContainerView buffer) const = 0;

 private:
#define DefineUnaryFunc(FuncName)               \
  auto FuncName(const Item& x) const override { \
    return FuncName(x.AsSpan<T>());             \
  }

#define DefineUnaryInplaceFunc(FuncName) \
  void FuncName(Item* x) const override { return FuncName(x->AsSpan<T>()); }

#define DefineBinaryFunc(FuncName)                             \
  auto FuncName(const Item& x, const Item& y) const override { \
    return FuncName(x.AsSpan<T>(), y.AsSpan<T>());             \
  }

#define DefineBinaryInplaceFunc(FuncName)                \
  void FuncName(Item* x, const Item& y) const override { \
    FuncName(x->AsSpan<T>(), y.AsSpan<T>());             \
  }

  // if x is scalar, returns bool
  // if x is vectored, returns std::vector<bool>
  DefineUnaryFunc(IsIdentityOne);
  DefineUnaryFunc(IsIdentityZero);
  DefineUnaryFunc(IsInField);
  DefineBinaryFunc(Equal);

  //==================================//
  //   operations defined on field    //
  //==================================//

  // get the additive inverse −a for all elements in set
  DefineUnaryFunc(Neg);
  DefineUnaryInplaceFunc(NegInplace);

  // get the multiplicative inverse 1/b for every nonzero element in set
  DefineUnaryFunc(Inv);
  DefineUnaryInplaceFunc(InvInplace);

  DefineBinaryFunc(Add);
  DefineBinaryInplaceFunc(AddInplace);

  DefineBinaryFunc(Sub);
  DefineBinaryInplaceFunc(SubInplace);

  DefineBinaryFunc(Mul);
  DefineBinaryInplaceFunc(MulInplace);

  DefineBinaryFunc(Div);
  DefineBinaryInplaceFunc(DivInplace);

  virtual Item Pow(const Item& x, const MPInt& y) const {
    return Pow(x.AsSpan<T>(), y);
  }

  virtual void PowInplace(Item* x, const MPInt& y) const {
    PowInplace(x->AsSpan<T>(), y);
  }

  Item Random() const override { return RandomT(1)[0]; }

  Item Random(size_t count) const override { return RandomT(count); }

  //================================//
  //              I/O               //
  //================================//

  DefineUnaryFunc(DeepCopy);

  // To human-readable string
  DefineUnaryFunc(ToString);
  DefineUnaryFunc(Serialize);

  // serialize field element(s) to already allocated buffer.
  // if buf is nullptr, then calc serialize size only
  // @return: the actual size of serialized buffer
  virtual size_t Serialize(const Item& x, uint8_t* buf, size_t buf_len) const {
    return Serialize(x.AsSpan<T>(), buf, buf_len);
  }

  virtual Item Deserialize(ByteContainerView buffer) const {
    return DeserializeT(buffer);
  }
};

}  // namespace yacl::math
