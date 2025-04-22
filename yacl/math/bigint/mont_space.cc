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

#include "yacl/math/bigint/mont_space.h"

#include "absl/cleanup/cleanup.h"

namespace yacl::math {

namespace {
bool IsNegative(const BigIntVar& n) {
  return std::visit([](const auto& a) { return a.IsNegative(); }, n);
}

bool IsOdd(const BigIntVar& n) {
  return std::visit([](const auto& a) { return a.IsOdd(); }, n);
}

size_t BitCount(const BigIntVar& n) {
  return std::visit([](const auto& a) { return a.BitCount(); }, n);
}
}  // namespace

MontgomerySpace::MontgomerySpace(const BigIntVar& mod) {
  YACL_ENFORCE(!IsNegative(mod) && IsOdd(mod),
               "modulus must be a positive odd number");
}

void MontgomerySpace::MakeBaseTable(const BigIntVar& base, size_t unit_bits,
                                    size_t max_exp_bits,
                                    BaseTable* out_table) const {
  YACL_ENFORCE(!IsNegative(base),
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

  BigIntVar now = base;
  // now = g * R mod m, i.e. g^1 in Montgomery form
  MapIntoMSpace(now);
  for (size_t outer = 0; outer < max_exp_stairs; ++outer) {
    BigIntVar level_base = now;
    for (size_t inner = 0; inner < out_table->exp_unit_expand - 1; ++inner) {
      out_table->stair.push_back(now);
      now = MulMod(now, level_base);
    }
  }
}

BigIntVar MontgomerySpace::PowMod(const BaseTable& base,
                                  const BigIntVar& e) const {
  YACL_ENFORCE(!IsNegative(e) && BitCount(e) <= base.exp_max_bits,
               "exponent is too big, max_allowed={}, real_exp={}",
               base.exp_max_bits, BitCount(e));
  auto [words, num_words, need_free] = GetWords(e);
  size_t word_bits = GetWordBitSize();
  // Captured structured bindings are a C++20 extension
  const uint64_t* words_cpy = words;
  bool free_cpy = need_free;
  absl::Cleanup guard([words_cpy, free_cpy]() {
    if (free_cpy) {
      delete[] words_cpy;
    }
  });
  BigIntVar r = Identity();
  size_t level = 0;
  uint64_t e_unit = 0;
  // Store unprocessed bits of the previous digit
  size_t unit_start_bits = 0;
  for (size_t i = 0; i < num_words; ++i) {
    uint64_t word = words[i];
    // Process the last digit remnant
    uint_fast16_t drop_bits = base.exp_unit_bits - unit_start_bits;
    if (unit_start_bits > 0) {
      // Take the low 'drop_bits' bits of digit
      // and add to the high bits of 'e_unit'
      e_unit |= (word << drop_bits) & base.exp_unit_mask;
      word >>= unit_start_bits;

      if (e_unit > 0) {
        r = MulMod(r, base.stair[level + e_unit - 1]);
      }
      level += (base.exp_unit_expand - 1);
    }

    // Continue processing the current digit
    for (; unit_start_bits <= word_bits - base.exp_unit_bits;
         unit_start_bits += base.exp_unit_bits) {
      e_unit = word & base.exp_unit_mask;
      word >>= base.exp_unit_bits;

      if (e_unit > 0) {
        r = MulMod(r, base.stair[level + e_unit - 1]);
      }

      level += (base.exp_unit_expand - 1);
    }

    unit_start_bits = unit_start_bits == word_bits
                          ? 0
                          : unit_start_bits + base.exp_unit_bits - word_bits;
    e_unit = word;
  }

  // Process the last remaining
  if (unit_start_bits > 0 && e_unit > 0) {
    r = MulMod(r, base.stair[level + e_unit - 1]);
  }

  return r;
}

}  // namespace yacl::math
