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

#pragma once

#include <utility>
#include <vector>

#include "yacl/math/mpint/mp_int.h"

namespace examples::zkp {

enum class VariableType {
  Committed,
  MultiplierLeft,
  MultiplierRight,
  MultiplierOutput,
  One
};

struct Variable {
  VariableType type;
  size_t index; // Index for Committed and Multiplier variables

  Variable(VariableType type, size_t index = 0) : type(type), index(index) {}

  // Factory functions for convenience
  static Variable Committed(size_t index) { return {VariableType::Committed, index}; }
  static Variable MultiplierLeft(size_t index) { return {VariableType::MultiplierLeft, index}; }
  static Variable MultiplierRight(size_t index) { return {VariableType::MultiplierRight, index}; }
  static Variable MultiplierOutput(size_t index) { return {VariableType::MultiplierOutput, index}; }
  static Variable One() { return {VariableType::One, 0}; }
  
  bool operator==(const Variable& other) const {
      return type == other.type && index == other.index;
  }
};

// Represents a linear combination of variables.
class LinearCombination {
 public:
  std::vector<std::pair<Variable, yacl::math::MPInt>> terms;

  LinearCombination() = default;
  LinearCombination(Variable var);
  LinearCombination(yacl::math::MPInt scalar);
  LinearCombination(std::vector<std::pair<Variable, yacl::math::MPInt>> terms);

  // Operator overloads to build linear combinations easily
  LinearCombination& operator+=(const LinearCombination& rhs);
  LinearCombination& operator-=(const LinearCombination& rhs);
  LinearCombination& operator*=(const yacl::math::MPInt& scalar);

  friend LinearCombination operator+(LinearCombination lhs, const LinearCombination& rhs);
  friend LinearCombination operator-(LinearCombination lhs, const LinearCombination& rhs);
  friend LinearCombination operator*(LinearCombination lhs, const yacl::math::MPInt& scalar);
  friend LinearCombination operator*(const yacl::math::MPInt& scalar, LinearCombination rhs);
  friend LinearCombination operator-(LinearCombination lc);
};

// Free function operators for convenience, e.g., var + var
LinearCombination operator+(Variable lhs, Variable rhs);
LinearCombination operator-(Variable lhs, Variable rhs);
LinearCombination operator*(Variable lhs, const yacl::math::MPInt& scalar);
LinearCombination operator*(const yacl::math::MPInt& scalar, Variable rhs);

} // namespace examples::zkp