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

#include "yacl/math/galois_field/factory/mpint_factory.h"

#include "yacl/math/galois_field/gf.h"

namespace yacl::math {

REGISTER_GF_LIBRARY(kMPIntLib, 100, MPIntField::Check, MPIntField::Create);

std::unique_ptr<GaloisField> MPIntField::Create(const std::string &field_name,
                                                const SpiArgs &args) {
  YACL_ENFORCE(field_name == kPrimeField);
  auto mod = args.GetRequired(ArgMod);
  YACL_ENFORCE(mod.IsPrime(), "ArgMod must be a prime");
  return std::unique_ptr<MPIntField>(new MPIntField(std::move(mod)));
}

bool MPIntField::Check(const std::string &field_name, const SpiArgs &) {
  return field_name == kPrimeField;
}

std::string MPIntField::GetLibraryName() const { return kMPIntLib; }

std::string MPIntField::GetFieldName() const { return kPrimeField; }

MPInt MPIntField::GetOrder() const { return mod_; }

MPInt MPIntField::GetMulGroupOrder() const { return mod_ - 1_mp; }

MPInt MPIntField::GetAddGroupOrder() const { return mod_; }

uint64_t MPIntField::GetExtensionDegree() const { return 1; }

MPInt MPIntField::GetBaseFieldOrder() const { return mod_; }

Item MPIntField::GetIdentityZero() const { return MPInt::_0_; }

Item MPIntField::GetIdentityOne() const { return MPInt::_1_; }

bool MPIntField::IsIdentityOne(const MPInt &x) const { return x == MPInt::_1_; }

bool MPIntField::IsIdentityZero(const MPInt &x) const { return x.IsZero(); }

bool MPIntField::IsInField(const MPInt &x) const {
  return x.IsNatural() && x < mod_;
}

bool MPIntField::Equal(const MPInt &x, const MPInt &y) const { return x == y; }

//==================================//
//   operations defined on field    //
//==================================//

MPInt MPIntField::Add(const MPInt &x, const MPInt &y) const {
  return x.AddMod(y, mod_);
}

void MPIntField::AddInplace(MPInt *x, const MPInt &y) const {
  MPInt::AddMod(*x, y, mod_, x);
}

MPInt MPIntField::Neg(const MPInt &x) const {
  if (x.IsZero()) {
    return x;
  }

  WEAK_ENFORCE(IsInField(x), "x is not a valid field element, x={}", x);
  return mod_ - x;
}

void MPIntField::NegInplace(MPInt *x) const {
  if (x->IsZero()) {
    return;
  }

  WEAK_ENFORCE(IsInField(*x), "x is not a valid field element, x={}", *x);
  x->NegateInplace();
  AddInplace(x, mod_);
}

MPInt MPIntField::Inv(const MPInt &x) const { return x.InvertMod(mod_); }

void MPIntField::InvInplace(MPInt *x) const { MPInt::InvertMod(*x, mod_, x); }

MPInt MPIntField::Sub(const MPInt &x, const MPInt &y) const {
  return x.SubMod(y, mod_);
}

void MPIntField::SubInplace(MPInt *x, const MPInt &y) const {
  MPInt::SubMod(*x, y, mod_, x);
}

MPInt MPIntField::Mul(const MPInt &x, const MPInt &y) const {
  return x.MulMod(y, mod_);
}

void MPIntField::MulInplace(MPInt *x, const MPInt &y) const {
  MPInt::MulMod(*x, y, mod_, x);
}

MPInt MPIntField::Div(const MPInt &x, const MPInt &y) const {
  return x.MulMod(y.InvertMod(mod_), mod_);
}

void MPIntField::DivInplace(MPInt *x, const MPInt &y) const {
  MPInt::MulMod(*x, y.InvertMod(mod_), mod_, x);
}

MPInt MPIntField::Pow(const MPInt &x, const MPInt &y) const {
  return x.PowMod(y, mod_);
}

void MPIntField::PowInplace(MPInt *x, const MPInt &y) const {
  MPInt::PowMod(*x, y, mod_, x);
}

MPInt MPIntField::RandomT() const {
  MPInt res;
  MPInt::RandomLtN(mod_, &res);
  return res;
}

MPInt MPIntField::DeepCopy(const MPInt &x) const { return x; }

std::string MPIntField::ToString(const MPInt &x) const { return x.ToString(); }

size_t MPIntField::Serialize(const MPInt &x, uint8_t *buf,
                             size_t buf_len) const {
  return x.Serialize(buf, buf_len);
}

MPInt MPIntField::DeserializeT(ByteContainerView buffer) const {
  MPInt res;
  res.Deserialize(buffer);
  return res;
}

}  // namespace yacl::math
