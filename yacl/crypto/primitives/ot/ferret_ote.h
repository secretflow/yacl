// Copyright 2022 Ant Group Co., Ltd.
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

#include <cstdint>
#include <memory>
#include <unordered_map>
#include <vector>

#include "yacl/crypto/primitives/ot/ot_store.h"
#include "yacl/crypto/utils/math.h"
#include "yacl/utils/cuckoo_index.h"

namespace yacl::crypto {

using FerretSimpleMap = std::vector<std::unordered_map<uint64_t, uint64_t>>;

enum class LpnNoiseAsm { RegularNoise, UniformNoise };

// For more parameter choices, see results in
// https://eprint.iacr.org/2019/273.pdf Page 20, Table 1.
class LpnParam {
 public:
  LpnNoiseAsm noise_asm = LpnNoiseAsm::RegularNoise;
  uint64_t n = 10485760;  // primal lpn, security param = 128
  uint64_t k = 452000;    // primal lpn, security param = 128
  uint64_t t = 1280;      // primal lpn, security param = 128
  static LpnParam GetDefault() {
    return {LpnNoiseAsm::RegularNoise, 10485760, 452000, 1280};
  }
};

// Single-Point Correlated OT ("length") Extension Implementation
//
// This implementation bases on Ferret, for more theoretical details, see
// https://eprint.iacr.org/2020/924.pdf, section 4, figure 6.
//
//              +---------+    +------------+
//              |   COT   | => |   SP-COT   |
//              +---------+    +------------+
//              num = t           num = 1
//              len = kappa       len = 2^t (denote as n)
//
//  > kappa: computation security parameter (128 for example)
//
// Threat Model:
//  > Passive Adversary
//
// Security assumptions:
//  > SGRR OTE (n-1 out of n OT Extension)
//      - see `yacl/crypto/primitives/ot/sgrr_ote.h`
//
class SpCotOption {
 public:
  uint64_t idx_range = 0;  // range of the point
  uint64_t cot_num = 0;    // required cot_num
};

inline SpCotOption MakeSpCotOption(uint64_t idx_range) {
  return {idx_range, Log2Ceil(idx_range)};
}

void SpCotSend(const std::shared_ptr<link::Context>& ctx,
               const OtSendStore& cot, const SpCotOption& option,
               absl::Span<uint128_t> out);

void SpCotRecv(const std::shared_ptr<link::Context>& ctx,
               const OtRecvStore& cot, const SpCotOption& option, uint64_t idx,
               absl::Span<uint128_t> out);

// Multi-Point Correlated OT ("length") Extension Implementation
//
// This implementation bases on Ferret, for more theoretical details, see
// https://eprint.iacr.org/2020/924.pdf, section 4, figure 6.
//
//              +---------+    +------------+
//              |   COT   | => |   MP-COT   |
//              +---------+    +------------+
//              num = n           num = t
//              len = kappa       len = 2^n
//
//  > kappa: computation security parameter (128 for example)
//
// Threat Model:
//  > Passive Adversary
//
// Security assumptions:
//  > SpCotSend / SpCotRecv (see previous codes in this file)

class MpCotOption {
 public:
  uint64_t idx_num = 0;    // number of points
  uint64_t idx_range = 0;  // range of the points
  uint64_t cot_num = 0;    // required cot_num

  // whether to use cuckoo hashing (experimental, not that we only
  // use cuckoo mpcot with uniform lpn noise assumption)
  bool use_cuckoo = false;

  // if use_cuckoo is set to true, MpCotOption use two additional options
  CuckooIndex::Options cuckoo_option;
  std::unique_ptr<FerretSimpleMap> simple_map = nullptr;  // the pointer
};

// Note: In ferret OT we can set use_cuckoo = false, which leverages the
// assumption of regular lpn noise
MpCotOption MakeMpCotOption(uint64_t idx_num, uint64_t idx_range,
                            bool use_cuckoo = false);

void MpCotSend(const std::shared_ptr<link::Context>& ctx,
               const OtSendStore& cot, const MpCotOption& option,
               absl::Span<uint128_t> out);

void MpCotRecv(const std::shared_ptr<link::Context>& ctx,
               const OtRecvStore& cot, const MpCotOption& option,
               absl::Span<const uint64_t> idxes, absl::Span<uint128_t> out);

// Ferret OT Extension Implementation
//
// This implementation bases on Ferret OTE, for more theoretical details, see
// https://eprint.iacr.org/2020/924.pdf, section 6, figure 9. Note that our
// implementation is not exactly the same since original protocol uses ideal ot
// functionality (not random ot).
//
//              +---------+    +---------+
//              |   COT   | => |   COT   |
//              +---------+    +---------+
//              num = m*       num = n
//              len = kappa    len = kappa
//
//  > kappa: computation security parameter (128 for example)
//  > We provide a function `MakeFerretOtExtOption` to help user to calculate
//  the required cot numbers with his/her desired cot numbers.
//
// Security assumptions:
//  > Correlation-robust hash function, for more details about its
//  implementation, see `yacl/crypto-tools/random_permutation.h`
// > Primal LPN, for more details, please see the original paper

class FerretOtExtOption {
 public:
  LpnParam lpn_param;        // lpn parameters
  uint64_t cot_num = 0;      // the required cot_num
  MpCotOption mpcot_option;  // internal mpcot options
};

FerretOtExtOption MakeFerretOtExtOption(const LpnParam& lpn_param,
                                        uint64_t ot_num);

std::shared_ptr<OtSendStore> FerretOtExtSend(
    const std::shared_ptr<link::Context>& ctx, const OtSendStore& base_cot,
    const FerretOtExtOption& option, uint64_t ot_num);

std::shared_ptr<OtRecvStore> FerretOtExtRecv(
    const std::shared_ptr<link::Context>& ctx, const OtRecvStore& base_cot,
    const FerretOtExtOption& option, uint64_t ot_num);

// inline std::shared_ptr<OtSendStore> FerretOtExtSend(
//     const std::shared_ptr<link::Context>& ctx,
//     const OtSendStore& base_cot, const LpnParam& lpn_param,
//     uint64_t ot_num) {
//   auto option = MakeFerretOtExtOption(lpn_param, ot_num);
//   return FerretOtExtSend(ctx, base_cot, option, ot_num);
// }

// inline std::shared_ptr<OtRecvStore> FerretOtExtRecv(
//     const std::shared_ptr<link::Context>& ctx,
//     const OtRecvStore& base_cot, const LpnParam& lpn_param,
//     uint64_t ot_num) {
//   auto option = MakeFerretOtExtOption(lpn_param, ot_num);
//   return FerretOtExtRecv(ctx, base_cot, option, ot_num);
// }

}  // namespace yacl::crypto
