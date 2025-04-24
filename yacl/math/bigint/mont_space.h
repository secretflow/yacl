// Copyright 2024 Ant Group Co., Ltd.
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

#include "yacl/math/bigint/bigint_var.h"

namespace yacl::math {

// Handle scenarios with a fixed base, and store the decomposed base
class BaseTable {
 public:
  size_t exp_unit_bits;    // Number of exponent bits to process at one time
  size_t exp_unit_expand;  // Cache table width, equal to 2^(exp_unit_bits)
  size_t exp_unit_mask;    // Equal to exp_unit_expand - 1
  // The maximum allowed exponent, used to determine whether the stair array
  // will be out of bounds
  size_t exp_max_bits;
  std::vector<BigIntVar> stair;
};

class MontgomerySpace {
 public:
  explicit MontgomerySpace(const BigIntVar& mod);

  virtual ~MontgomerySpace() = default;

  virtual BigIntVar Identity() const = 0;

  // Map x to M-ring: x -> xR
  virtual void MapIntoMSpace(BigIntVar& a) const = 0;

  // Map x to Z-ring: xR -> x
  virtual void MapBackToZSpace(BigIntVar& a) const = 0;

  /**
   * @brief Calculate abR^-1 mod m
   * @note a,b are all in Montgomery ring
   */
  virtual BigIntVar MulMod(const BigIntVar& a, const BigIntVar& b) const = 0;

  /**
   * @brief Calculate (base^e)R mod m
   * @param[in] base The cache table, which contains both base and modulus info
   * @param[in] e The exponent
   */
  BigIntVar PowMod(const BaseTable& base, const BigIntVar& e) const;

  /**
   * @brief Build a cache table
   * @param[in] base The base, must >= 0, (after cache table is constructed, the
   * base is immutable)
   * @param[in] unit_bits Exponent bits processed in one operation
   * @param[in] max_exp_bits Maximum allowed exponent size, which is linear with
   * cache table size
   * @param[out] out_table The result that contains the constructed cached table
   */
  void MakeBaseTable(const BigIntVar& base, size_t unit_bits,
                     size_t max_exp_bits, BaseTable* out_table) const;

  virtual size_t GetWordBitSize() const = 0;

 protected:
  struct Words {
    const uint64_t* data;
    size_t num_words;
    bool need_free;
  };

 private:
  virtual Words GetWords(const BigIntVar& e) const = 0;
};

}  // namespace yacl::math
