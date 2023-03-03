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

#include "tommath.h"

#include "yacl/crypto/base/mpint/mp_int.h"

namespace yacl::crypto {

#define CHECK_MP_ERR(MP_FUNC) \
  do {                        \
    auto err = (MP_FUNC);     \
    if (err != MP_OKAY) {     \
      return err;             \
    }                         \
  } while (0)

// Handle scenarios with a fixed base, and store the decomposed base
class BaseTable {
 public:
  size_t exp_unit_bits;    // Number of exponent bits to process at one time
  size_t exp_unit_expand;  // Cache table width, equal to 2^(exp_unit_bits)
  size_t exp_unit_mask;    // Equal to exp_unit_expand - 1
  // The maximum allowed exponent, used to determine whether the stair array
  // will be out of bounds
  size_t exp_max_bits;
  std::vector<MPInt> stair;

  size_t MemAllocated() {
    if (stair.empty()) {
      return sizeof(BaseTable);
    }

    return stair.capacity() * stair[stair.size() - 1].SizeAllocated() +
           sizeof(BaseTable);
  }

  size_t MemUsed() {
    if (stair.empty()) {
      return sizeof(BaseTable);
    }

    return stair.size() * stair[stair.size() - 1].SizeUsed() +
           sizeof(BaseTable);
  }

  std::string ToString() {
    return fmt::format(
        "BaseTable {}x{}, step {}bits, up to {}bits, mem used {}KB/{}KB",
        exp_unit_expand, (exp_max_bits + exp_unit_bits - 1) / exp_unit_bits,
        exp_unit_bits, exp_max_bits, MemUsed() / 1024, MemAllocated() / 1024);
  }
};

class MontgomerySpace {
 public:
  explicit MontgomerySpace(const MPInt& mod);

  void MapIntoMSpace(MPInt* x) const;    // Map x to M-ring: x -> xR
  void MapBackToZSpace(MPInt* x) const;  // Map x to Z-ring: xR -> x

  MPInt GetIdentity() const { return identity_; }

  /**
   * @brief Build a cache table
   * @param[in] base The base, must >= 0, (after cache table is constructed, the
   * base is immutable)
   * @param[in] unit_bits Exponent bits processed in one operation
   * @param[in] max_exp_bits Maximum allowed exponent size, which is linear with
   * cache table size
   * @param[out] out_table The result that contains the constructed cached table
   */
  void MakeBaseTable(const MPInt& base, size_t unit_bits, size_t max_exp_bits,
                     BaseTable* out_table) const;

  /**
   * @brief Calculate (base^e)R mod m
   * @param[in] base The cache table, which contains both base and modulus info
   * @param[in] e The exponent
   * @param[out] out  The result in Montgomery ring
   * @warning 'e' and 'out' should not point to the same variable
   */
  void PowMod(const BaseTable& base, const MPInt& e, MPInt* out) const;

  /**
   * @brief Calculate abR^-1 mod m
   * @note a,b,y are all in Montgomery ring
   */
  void MulMod(const MPInt& a, const MPInt& b, MPInt* y) const;

 private:
  MPInt mod_;       // The original modulus (m)
  mp_digit mp_;     // mp = -m^-1 mod R
  MPInt identity_;  // identity = R mod m // i.e. unit 1 in Montgomery ring
};

}  // namespace yacl::crypto
