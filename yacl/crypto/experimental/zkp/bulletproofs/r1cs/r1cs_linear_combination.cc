// Copyright 2025 @yangjucai.
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

#include "yacl/crypto/experimental/zkp/bulletproofs/r1cs/r1cs_linear_combination.h"

namespace examples::zkp {

LinearCombination::LinearCombination(Variable var) {
  terms.emplace_back(var, yacl::math::MPInt(1));
}

LinearCombination::LinearCombination(yacl::math::MPInt scalar) {
  terms.emplace_back(Variable::One(), std::move(scalar));
}

LinearCombination::LinearCombination(
    std::vector<std::pair<Variable, yacl::math::MPInt>> terms)
    : terms(std::move(terms)) {}

LinearCombination& LinearCombination::operator+=(const LinearCombination& rhs) {
  terms.insert(terms.end(), rhs.terms.begin(), rhs.terms.end());
  return *this;
}

LinearCombination& LinearCombination::operator-=(const LinearCombination& rhs) {
  for (const auto& term : rhs.terms) {
    terms.emplace_back(term.first, -term.second);
  }
  return *this;
}

LinearCombination& LinearCombination::operator*=(
    const yacl::math::MPInt& scalar) {
  for (auto& term : terms) {
    term.second *= scalar;
  }
  return *this;
}

LinearCombination operator+(LinearCombination lhs,
                            const LinearCombination& rhs) {
  lhs += rhs;
  return lhs;
}

LinearCombination operator-(LinearCombination lhs,
                            const LinearCombination& rhs) {
  lhs -= rhs;
  return lhs;
}

LinearCombination operator*(LinearCombination lhs,
                            const yacl::math::MPInt& scalar) {
  lhs *= scalar;
  return lhs;
}

LinearCombination operator*(const yacl::math::MPInt& scalar,
                            LinearCombination rhs) {
  rhs *= scalar;
  return rhs;
}

LinearCombination operator-(LinearCombination lc) {
  for (auto& term : lc.terms) {
    term.second.NegateInplace();
  }
  return lc;
}

// Free function operators for convenience
LinearCombination operator+(Variable lhs, Variable rhs) {
  return LinearCombination(lhs) + LinearCombination(rhs);
}

LinearCombination operator-(Variable lhs, Variable rhs) {
  return LinearCombination(lhs) - LinearCombination(rhs);
}

LinearCombination operator*(Variable lhs, const yacl::math::MPInt& scalar) {
  return LinearCombination(lhs) * scalar;
}

LinearCombination operator*(const yacl::math::MPInt& scalar, Variable rhs) {
  return scalar * LinearCombination(rhs);
}

}  // namespace examples::zkp