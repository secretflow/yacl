// Copyright 2024 Ant Group Co., Ltd.
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

#include "yacl/crypto/experimental/dpf/pprf.h"

#include <math.h>

#include <limits>

#include "spdlog/spdlog.h"

#include "yacl/base/exception.h"
#include "yacl/base/int128.h"
#include "yacl/crypto/tools/prg.h"

namespace yacl::crypto {

namespace {
void GgmPrg(uint128_t in, uint128_t* out1, uint128_t* out2) {
  if (out1 != nullptr) {
    FillPRand(SymmetricCrypto::CryptoType::AES128_CTR, in, 0, 0, (char*)out1,
              sizeof(uint128_t));
  }
  if (out2 != nullptr) {
    FillPRand(SymmetricCrypto::CryptoType::AES128_CTR, in, 0, 1, (char*)out2,
              sizeof(uint128_t));
  }
}

[[maybe_unused]] void GgmFullExpand(absl::Span<uint128_t> working_span) {
  const size_t num = working_span.size();
  if (num > 1) {
    GgmPrg(working_span[0], &working_span[0], &working_span[num / 2]);
    GgmFullExpand(working_span.subspan(0, num / 2));
    GgmFullExpand(working_span.subspan(num / 2, num / 2));
  } else {
    // SPDLOG_INFO(working_span[0]); /* for debug */
  }
}

template <size_t M>
void GgmExpandAndPunc(absl::Span<uint128_t> working_span, GE2n<M> punc_point,
                      PprfPuncKey* out) {
  const size_t num = working_span.size();  // total number of levels
  const size_t i = M - log2<size_t>(num);  // current level, starting from 0
  if (num > 1) {
    GgmPrg(working_span[0], &working_span[0], &working_span[num / 2]);
    if (!punc_point.GetBit(i)) { /* 0 means left */
      GgmExpandAndPunc(working_span.subspan(0, num / 2), punc_point, out);
      out->seeds.insert({i, working_span[num / 2]});
    } else {
      out->seeds.insert({i, working_span[0]});
      GgmExpandAndPunc(working_span.subspan(num / 2, num / 2), punc_point, out);
    }
  } else {
    // SPDLOG_INFO("({}, {})", i, working_span[0]); /* for debug */
  }
}

}  // namespace

template <size_t /* input bit num */ M, size_t /* output bit num */ N>
void PprfPunc(uint128_t prf_key, GE2n<M> punc_point, PprfPuncKey* out) {
  static_assert(M <= 64);
  uint64_t m = M;  // m is a runtime var
  uint64_t num =
      (m == 64) ? std::numeric_limits<size_t>::max() : (uint64_t)1 << m;

  std::vector<uint128_t> working_vec(num);
  working_vec[0] = prf_key;
  GgmExpandAndPunc(absl::MakeSpan(working_vec), punc_point, out);
  out->punc_point = punc_point.GetVal();
}

template <size_t /* input bit num */ M, size_t /* output bit num */ N>
void PprfPuncEval(const PprfPuncKey& punc_key, GE2n<M> point, GE2n<N>* out) {
  static_assert(M <= 64);
  GE2n<M> punc_point(punc_key.punc_point);
  YACL_ENFORCE(
      punc_point != point,
      "You cannot evaluate the already-punctured point with PprfPuncEval!");

  bool is_same = true;
  bool retrived = false;
  uint128_t current_seed = 0;
  for (size_t i = 0; i < M; ++i) {
    is_same &= point.GetBit(i) == punc_point.GetBit(i);
    if (!is_same) {
      if (!retrived) {
        current_seed = punc_key.seeds.at(i);
        retrived = true;
      } else {
        if (!point.GetBit(i)) { /* 0 means left */
          GgmPrg(current_seed, &current_seed, nullptr);
        } else {
          GgmPrg(current_seed, nullptr, &current_seed);
        }
        // SPDLOG_INFO(current_seed);
      }
    }
  }
  *out = GE2n<N>(current_seed);
}

template <size_t /* input bit num */ M, size_t /* output bit num */ N>
void PprfEval(uint128_t prf_key, GE2n<M> point, GE2n<N>* out) {
  static_assert(M <= 64);

  uint128_t current_seed = prf_key;
  for (size_t i = 0; i < M; ++i) {
    if (!point.GetBit(i)) { /* 0 means left */
      GgmPrg(current_seed, &current_seed, nullptr);
    } else {
      GgmPrg(current_seed, nullptr, &current_seed);
    }
  }
  *out = GE2n<N>(current_seed);
}

// template specification for different M and N
//
#define PPRF_T_SPECIFY_FUNC(M, N)                                              \
  template void PprfPunc<M, N>(uint128_t prf_key, GE2n<M> punc_point,          \
                               PprfPuncKey * out);                             \
  template void PprfPuncEval<M, N>(const PprfPuncKey& punc_key, GE2n<M> point, \
                                   GE2n<N>* out);                              \
  template void PprfEval<M, N>(uint128_t prf_key, GE2n<M> point, GE2n<N> * out);

PPRF_T_SPECIFY_FUNC(64, 64)
PPRF_T_SPECIFY_FUNC(32, 64)
PPRF_T_SPECIFY_FUNC(16, 64)
PPRF_T_SPECIFY_FUNC(8, 64)
PPRF_T_SPECIFY_FUNC(4, 64)
PPRF_T_SPECIFY_FUNC(2, 64)

PPRF_T_SPECIFY_FUNC(64, 128)
PPRF_T_SPECIFY_FUNC(32, 128)
PPRF_T_SPECIFY_FUNC(16, 128)
PPRF_T_SPECIFY_FUNC(8, 128)
PPRF_T_SPECIFY_FUNC(4, 128)
PPRF_T_SPECIFY_FUNC(2, 128)

#undef PPRF_T_SPECIFY_FUNC

}  // namespace yacl::crypto
