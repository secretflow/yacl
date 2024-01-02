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

#include <cstddef>
#include <cstdint>

#include "yacl/math/mpint/mp_int.h"
#include "yacl/utils/spi/item.h"
#include "yacl/utils/spi/spi_factory.h"

namespace yacl::math {

class GaloisField {
 public:
  virtual ~GaloisField() = default;

  //================================//
  //         meta info query        //
  //================================//

  virtual std::string GetLibraryName() const = 0;
  virtual std::string GetFieldName() const = 0;

  // The order of Finite Field will always be k-th power(p^k) of a prime number
  // p. And in extension field, field order and field modulus are different and
  // not directly related, which is unlike in normal prime field that field
  // order is just field modulus.
  // !Note, we will set the default order to be 0 for extension field, since the
  // origin order(p^k) of extension field(degree k>1) is actually useless for
  // field computation. Actually, we often deal within a subgroup(additive or
  // multiplicative) over the extension field, so we provide the other two
  // interfaces for `order`(GetMulGroupOrder and GetAddGroupOrder).
  virtual MPInt GetOrder() const = 0;
  virtual uint64_t GetExtensionDegree() const = 0;  // the k of GF(p^k)
  virtual MPInt GetBaseFieldOrder() const = 0;      // the p of GF(p^k)
  // Get order of a multiplicative (sub)group over field
  virtual MPInt GetMulGroupOrder() const = 0;
  // Get order of a additive (sub)group over field
  virtual MPInt GetAddGroupOrder() const = 0;

  // get the additive identity
  virtual Item GetIdentityZero() const = 0;
  // get the multiplicative identity
  virtual Item GetIdentityOne() const = 0;

  // Below functions:
  //  - if x is scalar, returns bool
  //  - if x is vectored, returns std::vector<bool>
  virtual Item IsIdentityOne(const Item& x) const = 0;
  virtual Item IsIdentityZero(const Item& x) const = 0;
  virtual Item IsInField(const Item& x) const = 0;

  virtual bool Equal(const Item& x, const Item& y) const = 0;

  //==================================//
  //   operations defined on field    //
  //==================================//

  // get the additive inverse −a for all elements in set
  virtual Item Neg(const Item& x) const = 0;
  virtual void NegInplace(Item* x) const = 0;

  // get the multiplicative inverse 1/b for every nonzero element in set
  virtual Item Inv(const Item& x) const = 0;
  virtual void InvInplace(Item* x) const = 0;

  virtual Item Add(const Item& x, const Item& y) const = 0;
  virtual void AddInplace(Item* x, const Item& y) const = 0;

  virtual Item Sub(const Item& x, const Item& y) const = 0;
  virtual void SubInplace(Item* x, const Item& y) const = 0;

  virtual Item Mul(const Item& x, const Item& y) const = 0;
  virtual void MulInplace(Item* x, const Item& y) const = 0;

  virtual Item Div(const Item& x, const Item& y) const = 0;
  virtual void DivInplace(Item* x, const Item& y) const = 0;

  virtual Item Pow(const Item& x, const MPInt& y) const = 0;
  virtual void PowInplace(Item* x, const MPInt& y) const = 0;

  // scalar version: return a random scalar element
  virtual Item Random() const = 0;
  // vector version: return a vector of 'count' elements
  virtual Item Random(size_t count) const = 0;

  //================================//
  //              I/O               //
  //================================//

  virtual Item DeepCopy(const Item& x) const = 0;

  // To human-readable string
  virtual std::string ToString(const Item& x) const = 0;

  virtual Buffer Serialize(const Item& x) const = 0;
  // serialize field element(s) to already allocated buffer.
  // if buf is nullptr, then calc serialize size only
  // @return: the actual size of serialized buffer
  virtual size_t Serialize(const Item& x, uint8_t* buf,
                           size_t buf_len) const = 0;

  virtual Item Deserialize(ByteContainerView buffer) const = 0;
};

class GaloisFieldFactory final : public SpiFactoryBase<GaloisField> {
 public:
  static GaloisFieldFactory& Instance();
};

#define REGISTER_GF_LIBRARY(lib_name, performance, checker, creator)     \
  REGISTER_SPI_LIBRARY_HELPER(GaloisFieldFactory, lib_name, performance, \
                              checker, creator)

}  // namespace yacl::math
