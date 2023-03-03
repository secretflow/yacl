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

#include "yacl/crypto/base/mpint/montgomery_math.h"

namespace yacl::crypto {

MontgomerySpace::MontgomerySpace(const MPInt &mod) {
  YACL_ENFORCE(!mod.IsNegative() && mod.IsOdd(),
               "modulus must be a positive odd number");
  mod_ = mod;
  MPINT_ENFORCE_OK(mp_montgomery_setup(&mod_.n_, &mp_));
  MPINT_ENFORCE_OK(mp_montgomery_calc_normalization(&identity_.n_, &mod_.n_));
}

void MontgomerySpace::MapIntoMSpace(MPInt *x) const {
  MPINT_ENFORCE_OK(mp_mulmod(&x->n_, &identity_.n_, &mod_.n_, &x->n_));
}

void MontgomerySpace::MapBackToZSpace(MPInt *x) const {
  MPINT_ENFORCE_OK(mp_montgomery_reduce(&x->n_, &mod_.n_, mp_));
}

void MontgomerySpace::MulMod(const MPInt &a, const MPInt &b, MPInt *y) const {
  MPINT_ENFORCE_OK(mp_mul(&a.n_, &b.n_, &y->n_));
  MPINT_ENFORCE_OK(mp_montgomery_reduce(&y->n_, &mod_.n_, mp_));
}

void MontgomerySpace::MakeBaseTable(const MPInt &base, size_t unit_bits,
                                    size_t max_exp_bits,
                                    BaseTable *out_table) const {
  YACL_ENFORCE(!base.IsNegative(),
               "Cache table: base number must be zero or positive");
  YACL_ENFORCE(unit_bits > 0, "Cache table: unit_bits must > 0");

  // About stair storage format:
  // Assuming exp_unit_bits = 3, then out_table stores:
  // g^1, g^2, g^3, g^4, g^5, g^6, g^7
  // g^8，g^16, g^24, g^32, g^40, g^48, g^56,
  // g^64，g^128, g^192, ...
  // g^512, ...
  // ...
  //
  // Each group (line) has 2^exp_unit_bits - 1 number, flattened into a
  // one-dimensional array for storage
  out_table->stair.clear();
  out_table->exp_unit_bits = unit_bits;
  out_table->exp_unit_expand = 1U << unit_bits;
  out_table->exp_unit_mask = out_table->exp_unit_expand - 1;
  size_t max_exp_stairs = (max_exp_bits + unit_bits - 1) / unit_bits;
  out_table->exp_max_bits = max_exp_stairs * out_table->exp_unit_bits;
  out_table->stair.reserve(max_exp_stairs * (out_table->exp_unit_expand - 1));

  MPInt now;
  // now = g * R mod m, i.e. g^1 in Montgomery form
  MPINT_ENFORCE_OK(mp_mulmod(&base.n_, &identity_.n_, &mod_.n_, &now.n_));
  for (size_t outer = 0; outer < max_exp_stairs; ++outer) {
    MPInt level_base = now;
    for (size_t inner = 0; inner < out_table->exp_unit_expand - 1; ++inner) {
      out_table->stair.push_back(now);
      MulMod(now, level_base, &now);
    }
  }
}

void MontgomerySpace::PowMod(const BaseTable &base, const MPInt &e,
                             MPInt *out) const {
  YACL_ENFORCE(!e.IsNegative() && e.BitCount() <= base.exp_max_bits,
               "exponent is too big, max_allowed={}, real_exp={}",
               base.exp_max_bits, e.BitCount());
  YACL_ENFORCE(&e != out,
               "'e' and 'out' should not point to the same variable");

  *out = identity_;
  uint64_t level = 0;
  mp_digit e_unit = 0;
  // Store unprocessed bits of the previous digit
  size_t unit_start_bits = 0;
  for (int digit_idx = 0; digit_idx < e.n_.used; ++digit_idx) {
    mp_digit digit = e.n_.dp[digit_idx];
    // Process the last digit remnant
    uint_fast16_t drop_bits = base.exp_unit_bits - unit_start_bits;
    if (unit_start_bits > 0) {
      // Take the low 'drop_bits' bits of digit
      // and add to the high bits of 'e_unit'
      e_unit |= (digit << drop_bits) & base.exp_unit_mask;
      digit >>= unit_start_bits;

      if (e_unit > 0) {
        MulMod(*out, base.stair[level + e_unit - 1], out);
      }
      level += (base.exp_unit_expand - 1);
    }

    // continue processing the current digit
    for (; unit_start_bits <= MP_DIGIT_BIT - base.exp_unit_bits;
         unit_start_bits += base.exp_unit_bits) {
      e_unit = digit & base.exp_unit_mask;
      digit >>= base.exp_unit_bits;

      if (e_unit > 0) {
        MulMod(*out, base.stair[level + e_unit - 1], out);
      }

      level += (base.exp_unit_expand - 1);
    }

    unit_start_bits = unit_start_bits == MP_DIGIT_BIT
                          ? 0
                          : unit_start_bits + base.exp_unit_bits - MP_DIGIT_BIT;
    e_unit = digit;
  }

  // process the last remaining
  if (unit_start_bits > 0 && e_unit > 0) {
    MulMod(*out, base.stair[level + e_unit - 1], out);
  }
}

}  // namespace yacl::crypto
