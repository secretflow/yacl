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

#include "yacl/crypto/base/ecc/group_sketch.h"

namespace yacl::crypto {

void EcGroupSketch::AddInplace(EcPoint *p1, const EcPoint &p2) const {
  *p1 = Add(*p1, p2);
}

EcPoint EcGroupSketch::Sub(const EcPoint &p1, const EcPoint &p2) const {
  return Add(p1, Negate(p2));
}

void EcGroupSketch::SubInplace(EcPoint *p1, const EcPoint &p2) const {
  AddInplace(p1, Negate(p2));
}

EcPoint EcGroupSketch::Double(const EcPoint &p) const { return Mul(p, 2_mp); }

void EcGroupSketch::DoubleInplace(EcPoint *p) const { MulInplace(p, 2_mp); }

EcPoint EcGroupSketch::MulBase(const MPInt &scalar) const {
  return Mul(GetGenerator(), scalar);
}

void EcGroupSketch::MulInplace(EcPoint *point, const MPInt &scalar) const {
  *point = Mul(*point, scalar);
}

EcPoint EcGroupSketch::MulDoubleBase(const MPInt &s1, const MPInt &s2,
                                     const EcPoint &p2) const {
  return Add(MulBase(s1), Mul(p2, s2));
}

EcPoint EcGroupSketch::Div(const EcPoint &point, const MPInt &scalar) const {
  YACL_ENFORCE(!scalar.IsZero(), "Ecc point can not div by zero!");

  if (scalar.IsPositive()) {
    return Mul(point, scalar.InvertMod(GetOrder()));
  }

  auto res = Mul(point, scalar.Abs().InvertMod(GetOrder()));
  return Negate(res);
}

void EcGroupSketch::DivInplace(EcPoint *point, const MPInt &scalar) const {
  YACL_ENFORCE(!scalar.IsZero(), "Ecc point can not div by zero!");

  if (scalar.IsPositive()) {
    MulInplace(point, scalar.InvertMod(GetOrder()));
    return;
  }

  MulInplace(point, scalar.Abs().InvertMod(GetOrder()));
  NegateInplace(point);
}

void EcGroupSketch::NegateInplace(EcPoint *point) const {
  *point = Negate(*point);
}

}  // namespace yacl::crypto
