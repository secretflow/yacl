// Copyright 2023 Ant Group Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

#include <sys/types.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <functional>
#include <numeric>
#include <vector>

#include "absl/types/span.h"
#include "spdlog/spdlog.h"

#include "yacl/base/block.h"
#include "yacl/base/exception.h"
#include "yacl/base/int128.h"
#include "yacl/kernel/code/code_interface.h"
#include "yacl/kernel/code/linear_code.h"

namespace yacl::crypto {

class ExAccCodeInterface : public LinearCodeInterface {
 public:
  ExAccCodeInterface(const ExAccCodeInterface &) = delete;
  ExAccCodeInterface &operator=(const ExAccCodeInterface &) = delete;
  ExAccCodeInterface() = default;
  virtual ~ExAccCodeInterface() = default;

  virtual uint32_t GetWeight() const = 0;

  virtual void DualEncode(absl::Span<uint128_t> in, /* GF(2^128) */
                          absl::Span<uint128_t> out) const = 0;
  virtual void DualEncode2(absl::Span<uint128_t> in0, /* GF(2^128) */
                           absl::Span<uint128_t> out0,
                           absl::Span<uint128_t> in1, /* GF(2^128) */
                           absl::Span<uint128_t> out1) const = 0;

  virtual void DualEncode(absl::Span<uint64_t> in, /* GF(2^64) */
                          absl::Span<uint64_t> out) const = 0;
  virtual void DualEncode2(absl::Span<uint64_t> in0, /* GF(2^64) */
                           absl::Span<uint64_t> out0,
                           absl::Span<uint64_t> in1, /* GF(2^64) */
                           absl::Span<uint64_t> out1) const = 0;

  virtual void DualEncode2(absl::Span<uint64_t> in0 /* GF(2^64) */,
                           absl::Span<uint64_t> out0,
                           absl::Span<uint128_t> in1, /* GF(2^128) */
                           absl::Span<uint128_t> out1) const = 0;
};

// Implementation of expand accumulate code in F2k, for more details, see
// original paper: https://eprint.iacr.org/2022/1014.pdf section 3.1
//
// In expand accumlate code (EAGenExa), matrix G = A * B, where A is an
// accumulator matrix and B is retangular whose column vectors are d-weight.
// Note that, "EAGenExa" is a special variant of "EAGen", more detail could be
// found in https://eprint.iacr.org/2022/1014.pdf section 3.4.
//
// For parameter choices, see analysis in https://eprint.iacr.org/2022/1014.pdf
// section 3.6.
//

template <size_t d = 7>
class ExAccCode : public ExAccCodeInterface {
 public:
  explicit ExAccCode(uint32_t n) : ExAccCode(n, 2 * n){};

  explicit ExAccCode(uint32_t n, uint32_t m) : n_(n), m_(m) {
    YACL_ENFORCE(m >= n);
    YACL_ENFORCE(n > d, "ExAccCode: Length should be much greater than Weight");
  };

  uint32_t GetDimention() const override { return m_; }

  uint32_t GetLength() const override { return n_; }

  uint32_t GetWeight() const override { return d; }

  // Expand Accumulate Code
  // dual LPN problem  --> G = A * B
  // thus, dual encode would be xG = (xA) * B = y * B, y[i] = sum_{j<=i} x[j]
  void DualEncode(absl::Span<uint128_t> in,
                  absl::Span<uint128_t> out) const override {
    DualEncodeImpl<uint128_t>(in, out);
  }

  void DualEncode2(absl::Span<uint128_t> in0, absl::Span<uint128_t> out0,
                   absl::Span<uint128_t> in1,
                   absl::Span<uint128_t> out1) const override {
    DualEncode2Impl<uint128_t, uint128_t>(in0, out0, in1, out1);
  }

  void DualEncode(absl::Span<uint64_t> in,
                  absl::Span<uint64_t> out) const override {
    DualEncodeImpl<uint64_t>(in, out);
  }

  void DualEncode2(absl::Span<uint64_t> in0, absl::Span<uint64_t> out0,
                   absl::Span<uint64_t> in1,
                   absl::Span<uint64_t> out1) const override {
    DualEncode2Impl<uint64_t, uint64_t>(in0, out0, in1, out1);
  }

  void DualEncode2(absl::Span<uint64_t> in0, absl::Span<uint64_t> out0,
                   absl::Span<uint128_t> in1,
                   absl::Span<uint128_t> out1) const override {
    DualEncode2Impl<uint64_t, uint128_t>(in0, out0, in1, out1);
  }

 private:
  uint32_t n_;
  uint32_t m_;
  const uint128_t seed_ = 0x12456789;
  const uint32_t weight_ = d;

  template <typename T>
  void DualEncodeImpl(absl::Span<T> in, absl::Span<T> out) const {
    YACL_ENFORCE(in.size() >= m_);
    YACL_ENFORCE(out.size() >= n_);

    // y[i] = sum_{j<=i} x[j]
    Accumulate<T>(in);
    // d-Local Linear Code
    Expand<T>(absl::MakeConstSpan(in), out);
  }

  template <typename T, typename K>
  void DualEncode2Impl(absl::Span<T> in0, absl::Span<T> out0, absl::Span<K> in1,
                       absl::Span<K> out1) const {
    YACL_ENFORCE(in0.size() >= m_);
    YACL_ENFORCE(in1.size() >= m_);

    YACL_ENFORCE(out0.size() >= n_);
    YACL_ENFORCE(out1.size() >= n_);

    // y[i] = sum_{j<=i} x[j]
    Accumulate<T>(in0);
    Accumulate<K>(in1);
    // d-Local Linear Code
    Expand2<T, K>(absl::MakeConstSpan(in0), out0, absl::MakeConstSpan(in1),
                  out1);
  }

  template <typename T>
  inline void Accumulate(absl::Span<T> inout) const {
    std::partial_sum(inout.cbegin(), inout.cend(), inout.begin(),
                     std::bit_xor<T>());
  }

  template <typename T>
  inline void Expand(absl::Span<const T> in, absl::Span<T> out) const {
    LocalLinearCode<d>(seed_, n_, m_).Encode(in, out);
  }

  template <typename T, typename K>
  inline void Expand2(absl::Span<const T> in0, absl::Span<T> out0,
                      absl::Span<const K> in1, absl::Span<K> out1) const {
    LocalLinearCode<d>(seed_, n_, m_).Encode2(in0, out0, in1, out1);
  }
};

};  // namespace yacl::crypto
