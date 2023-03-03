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

#include <string>
#include <vector>

namespace yacl::crypto {

// Some cryptographers (like Daniel Bernstein) believe that most of the curves,
// described in the official crypto-standards are "unsafe" and define their own
// crypto-standards, which consider the ECC security in much broader level.
//
// The Bernstein's SafeCurves standard lists the curves, which are safe
// according to a set of ECC security requirements. The standard is available at
// https://safecurves.cr.yp.to.
//
// For security reasons, we do not recommend users to implement their own curves
// or even standard curves.
using CurveName = std::string;

enum class CurveForm {
  // General form of elliptic curve
  // y^2 = x^3 + ax + b
  Weierstrass,
  // https://en.wikipedia.org/wiki/Montgomery_curve
  // By^2 = x^3 + Ax^2 +x
  Montgomery,
  // https://en.wikipedia.org/wiki/Edwards_curve
  // x^2 + y^2 = 1 + dx^2*y^2
  Edwards,
  // https://en.wikipedia.org/wiki/Twisted_Edwards_curve
  // ax^2 + y^2 = 1 + dx^2*y^2
  // The special case a=1 is untwisted, because the curve reduces to an ordinary
  // Edwards curve.
  TwistedEdwards,
};

enum class FieldType {
  // Non-binary Curves, define on E(F_p) where p is prime
  Prime,
  // Binary Curves, define on E(F_{2^m}), not recommend:
  // - Certicom has/had patents on these curves
  // - Security: Binary fields has more attack vectors than prime fields
  // Detail: https://crypto.stackexchange.com/q/91610
  Binary,
  // Curves define on E(F_{p^n})
  Extension,
};

struct CurveMeta {
  CurveName name;
  std::vector<CurveName> aliases;
  CurveForm form;
  FieldType field_type;
  size_t secure_bits;

  CurveName LowerName() const;
  bool IsEquivalent(CurveMeta rhs) const;
};

CurveMeta GetCurveMetaByName(const CurveName& name);

}  // namespace yacl::crypto
