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

#include "yacl/crypto/experimental/dpf/dpf.h"

#include <future>

#include "yacl/crypto/experimental/dpf/ge2n.h"
#include "yacl/secparam.h"
#include "yacl/utils/serializer.h"
#include "yacl/utils/serializer_adapter.h"

namespace yacl::crypto {

namespace {

template <size_t N>
GE2n<N> DpfPRG(uint128_t seed) {
  Prg<uint128_t, sizeof(uint128_t)> prng(seed);
  return GE2n<N>(prng());
}

std::tuple<uint128_t, bool, uint128_t, bool> SplitDpfSeed(uint128_t seed) {
  uint128_t seed_left = 0;
  uint128_t seed_right = 0;
  bool t_left;
  bool t_right;

  // TODO(@shanzhu.cjm): check if this implementation is secure and efficient
  Prg<uint128_t, 3 * sizeof(uint128_t)> prng(seed);

  seed_left = prng();
  seed_right = prng();
  uint128_t tmp = prng();

  t_left = tmp >> 1 & 1;
  t_right = tmp >> 2 & 1;

  return {seed_left, t_left, seed_right, t_right};
}

size_t GetTerminateLevel(bool enable_evalall, size_t m, size_t n) {
  if (!enable_evalall) {
    return m;
  }
  auto c = YACL_MODULE_SECPARAM_C_UINT("dpf");
  size_t x = ceil(m - log(c / n));
  return std::min(m, x);
}

template <size_t /* input bit num */ M, size_t /* output bit num */ N>
void Traverse(DpfKey* key, absl::Span<GE2n<N>> result, size_t current_level,
              uint64_t current_pos, uint128_t seed_working, bool t_working,
              size_t term_level) {
  if (current_level < term_level) {
    uint128_t seed_left;
    uint128_t seed_right;
    bool t_left;
    bool t_right;
    const auto cw_seed = key->cws_vec[current_level].GetSeed();
    const auto cw_t_left = key->cws_vec[current_level].GetLT();
    const auto cw_t_right = key->cws_vec[current_level].GetRT();

    std::tie(seed_left, t_left, seed_right, t_right) =
        SplitDpfSeed(seed_working);

    seed_left = t_working ? seed_left ^ cw_seed : seed_left;
    t_left = t_left ^ (t_working * cw_t_left);
    seed_right = t_working ? seed_right ^ cw_seed : seed_right;
    t_right = t_right ^ (t_working * cw_t_right);

    uint64_t next_left_pos = current_pos;
    uint64_t next_right_pos = (1ULL << current_level) + current_pos;

    Traverse<M, N>(key, result, current_level + 1, next_left_pos, seed_left,
                   t_left, term_level);
    Traverse<M, N>(key, result, current_level + 1, next_right_pos, seed_right,
                   t_right, term_level);

  } else {
    auto prg = DpfPRG<N>(seed_working);
    uint32_t expand_num = static_cast<uint32_t>(1) << (M - term_level);

    for (uint32_t i = 0; i < expand_num; i++) {
      auto tmp = GE2n<N>(t_working * key->last_cw_vec[i]);
      result[current_pos + (i << term_level)] =
          key->GetRank() ? (prg + tmp).GetReverse() : (prg + tmp);
      prg = DpfPRG<N>(prg.GetVal());
    }
  }
}

}  // namespace

// -----------------------------------------
// Full domain key generation and evaluation
// -----------------------------------------

template <size_t /* input bit num */ M, size_t /* output bit num */ N>
void DpfKeyGen(DpfKey* first_key, DpfKey* second_key, const GE2n<M>& alpha,
               const GE2n<N>& beta, uint128_t first_mk, uint128_t second_mk,
               bool enable_evalall) {
  static_assert(M > 0 && M <= 64);   // input bits number constrains
  static_assert(N > 0 && N <= 128);  // output bits number constrains

  // enable the early termination
  uint32_t term_level = GetTerminateLevel(enable_evalall, M, N);

  // set up the return keys
  *first_key = DpfKey(false, first_mk);
  *second_key = DpfKey(true, second_mk);
  first_key->cws_vec.resize(term_level);
  second_key->cws_vec.resize(term_level);

  std::array<uint128_t, 2> seeds_working;
  seeds_working[0] = first_mk;
  seeds_working[1] = second_mk;

  std::array<bool, 2> t_working;
  t_working[0] = false;  // default by definition
  t_working[1] = true;   // default by definition

  for (uint32_t i = 0; i < term_level; i++) {
    std::array<uint128_t, 2> seed_left;
    std::array<uint128_t, 2> seed_right;
    std::array<bool, 2> t_left;
    std::array<bool, 2> t_right;

    bool alpha_bit = (alpha.GetBit(i) != 0U);

    // Use working seed to generate seeds
    // Note: this is the most time-consuming process
    std::tie(seed_left[0], t_left[0], seed_right[0], t_right[0]) =
        SplitDpfSeed(seeds_working[0]);
    std::tie(seed_left[1], t_left[1], seed_right[1], t_right[1]) =
        SplitDpfSeed(seeds_working[1]);

    const auto keep_seed = alpha_bit ? seed_right : seed_left;
    const auto lose_seed = alpha_bit ? seed_left : seed_right;
    const auto t_keep = alpha_bit ? t_right : t_left;

    uint128_t cw_seed = lose_seed[0] ^ lose_seed[1];
    bool cw_t_left;
    bool cw_t_right;

    cw_t_left = t_left[0] ^ t_left[1] ^ alpha_bit ^ 1;
    cw_t_right = t_right[0] ^ t_right[1] ^ alpha_bit;
    const auto& cw_t_keep = alpha_bit ? cw_t_right : cw_t_left;

    // get the seeds_working and t_working for next level
    seeds_working[0] = t_working[0] ? keep_seed[0] ^ cw_seed : keep_seed[0];
    seeds_working[1] = t_working[1] ? keep_seed[1] ^ cw_seed : keep_seed[1];

    t_working[0] = t_keep[0] ^ t_working[0] * cw_t_keep;
    t_working[1] = t_keep[1] ^ t_working[1] * cw_t_keep;

    first_key->cws_vec[i].SetSeed(cw_seed);
    first_key->cws_vec[i].SetLT(cw_t_left);
    first_key->cws_vec[i].SetRT(cw_t_right);
  }

  // Expand final seed_working
  // get the final correlation words (has the same length as seeds)
  // notice the notation is `somewhat' incorrect in the original paper
  //
  // First, we get the Convert(S_0 ^ key_block) and Convert(S_1 ^ key_block)
  //
  auto prg0 = DpfPRG<N>(seeds_working[0]);
  auto prg1 = DpfPRG<N>(seeds_working[1]);

  // if !enable_evalall, we have only one last_cw_vec, otherwise, we
  // have multiple last_cw_vec
  YACL_ENFORCE(first_key->last_cw_vec.empty());
  YACL_ENFORCE(second_key->last_cw_vec.empty());

  if (!enable_evalall) {
    first_key->last_cw_vec.push_back(
        (beta + prg0.GetReverse() + prg1).GetVal());
    if (t_working[1]) {
      first_key->last_cw_vec[0] =
          GE2n<N>(first_key->last_cw_vec[0]).GetReverse().GetVal();
    }
    second_key->cws_vec = first_key->cws_vec;
    second_key->last_cw_vec.push_back(first_key->last_cw_vec[0]);
  } else {
    first_key->EnableEvalAll();
    second_key->EnableEvalAll();

    uint32_t alpha_pos_term_level = alpha.GetVal() >> term_level;
    uint32_t expand_num = static_cast<uint32_t>(1) << (M - term_level);

    for (uint32_t i = 0; i < expand_num; i++) {
      GE2n<N> last_cw;
      if (i == alpha_pos_term_level) {
        last_cw = beta + GE2n<N>(prg0).GetReverse() + prg1;
      } else {
        last_cw = GE2n<N>(prg0).GetReverse() + prg1;
      }

      if (t_working[1]) {
        first_key->last_cw_vec.push_back(last_cw.GetReverse().GetVal());
      } else {
        first_key->last_cw_vec.push_back(last_cw.GetVal());
      }

      second_key->cws_vec = first_key->cws_vec;
      second_key->last_cw_vec.push_back(first_key->last_cw_vec[i]);

      prg0 = DpfPRG<N>(prg0.GetVal());
      prg1 = DpfPRG<N>(prg1.GetVal());
    }
  }
}

template <size_t /* input bit num */ M, size_t /* output bit num */ N>
void DpfEval(const DpfKey& key, const GE2n<M>& in, GE2n<N>* out) {
  YACL_ENFORCE(key.enable_evalall == false);

  uint128_t seed_working = key.GetSeed();  // the initial value
  bool t_working = key.GetRank();          // the initial value

  for (uint32_t i = 0; i < M; i++) {
    const auto cw_seed = key.cws_vec[i].GetSeed();
    const auto cw_t_left = key.cws_vec[i].GetLT();
    const auto cw_t_right = key.cws_vec[i].GetRT();

    uint128_t seed_left;
    uint128_t seed_right;
    bool t_left;
    bool t_right;

    std::tie(seed_left, t_left, seed_right, t_right) =
        SplitDpfSeed(seed_working);

    seed_left = t_working ? seed_left ^ cw_seed : seed_left;
    t_left = t_left ^ (t_working * cw_t_left);
    seed_right = t_working ? seed_right ^ cw_seed : seed_right;
    t_right = t_right ^ (t_working * cw_t_right);

    if (in.GetBit(i) != 0U) {
      seed_working = seed_right;
      t_working = t_right;
    } else {
      seed_working = seed_left;
      t_working = t_left;
    }
  }

  auto prg = DpfPRG<N>(seed_working);

  auto tmp = GE2n<N>(t_working * key.last_cw_vec[0]);
  uint128_t result =
      key.GetRank() ? (prg + tmp).GetReverse().GetVal() : (prg + tmp).GetVal();

  *out = GE2n<N>(result);
}

template <size_t /* input bit num */ M, size_t /* output bit num */ N>
void DpfEvalAll(DpfKey* key, absl::Span<GE2n<N>> out) {
  YACL_ENFORCE(key->enable_evalall == true);

  uint128_t seed_working = key->GetSeed();  // the initial value
  bool t_working = key->GetRank();          // the initial value
  uint32_t term_level = GetTerminateLevel(true, M, N);

  auto num = (uint128_t)1 << M;
  std::vector<uint128_t> result(num);

  uint64_t current_pos = 0;
  uint64_t current_level = 0;  // we start from the top level

  Traverse<M, N>(key, out, current_level, current_pos, seed_working, t_working,
                 term_level);
}

// template specialization for different M and N
#define DPF_T_SPECIFY_FUNC(M, N)                                           \
  template void DpfKeyGen<M, N>(DpfKey * first_key, DpfKey * second_key,   \
                                const GE2n<M>& alpha, const GE2n<N>& beta, \
                                uint128_t first_mk, uint128_t second_mk,   \
                                bool enable_evalall = false);              \
                                                                           \
  template void DpfEval<M, N>(const DpfKey& key, const GE2n<M>& in,        \
                              GE2n<N>* out);                               \
                                                                           \
  template void DpfEvalAll<M, N>(DpfKey * key, absl::Span<GE2n<(N)>> out);

DPF_T_SPECIFY_FUNC(64, 64)
DPF_T_SPECIFY_FUNC(32, 64)
DPF_T_SPECIFY_FUNC(16, 64)
DPF_T_SPECIFY_FUNC(8, 64)
DPF_T_SPECIFY_FUNC(4, 64)
DPF_T_SPECIFY_FUNC(2, 64)
DPF_T_SPECIFY_FUNC(1, 64)

DPF_T_SPECIFY_FUNC(64, 128)
DPF_T_SPECIFY_FUNC(32, 128)
DPF_T_SPECIFY_FUNC(16, 128)
DPF_T_SPECIFY_FUNC(8, 128)
DPF_T_SPECIFY_FUNC(4, 128)
DPF_T_SPECIFY_FUNC(2, 128)
DPF_T_SPECIFY_FUNC(1, 128)

#undef DPF_T_SPECIFY_FUNC
}  // namespace yacl::crypto
