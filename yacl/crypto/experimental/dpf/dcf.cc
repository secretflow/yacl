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

#include "yacl/crypto/experimental/dpf/dcf.h"

#include <future>

#include "yacl/crypto/experimental/dpf/ge2n.h"
#include "yacl/secparam.h"
#include "yacl/utils/serializer.h"
#include "yacl/utils/serializer_adapter.h"

namespace yacl::crypto {

namespace {

template <size_t N>
GE2n<N> DcfPRG(uint128_t seed) {
  Prg<uint128_t, sizeof(uint128_t)> prng(seed);
  return GE2n<N>(prng());
}

std::tuple<uint128_t, uint128_t, bool, uint128_t, uint128_t, bool> SplitDcfSeed(
    uint128_t seed) {
  uint128_t seed_left = 0;
  uint128_t seed_right = 0;
  bool t_left;
  bool t_right;
  uint128_t v_seed_left;
  uint128_t v_seed_right;

  // TODO(@shanzhu.cjm): check if this implementation is secure and efficient
  Prg<uint128_t, 5 * sizeof(uint128_t)> prng(seed);

  seed_left = prng();
  seed_right = prng();
  v_seed_left = prng();
  v_seed_right = prng();
  uint128_t tmp = prng();

  t_left = tmp >> 1 & 1;
  t_right = tmp >> 2 & 1;

  return {seed_left, v_seed_left, t_left, seed_right, v_seed_right, t_right};
}

}  // namespace

// -----------------------------------------
// Full domain key generation and evaluation
// -----------------------------------------

template <size_t M, size_t N>
void DcfKeyGen(DcfKey* first_key, DcfKey* second_key, const GE2n<M>& alpha,
               const GE2n<N>& beta, uint128_t first_mk, uint128_t second_mk) {
  // enable the early termination
  const uint32_t term_level = M;

  // set up the return keys
  *first_key = DcfKey(false, first_mk);
  *second_key = DcfKey(true, second_mk);
  first_key->cws_vec.resize(term_level);
  second_key->cws_vec.resize(term_level);

  std::array<uint128_t, 2> seeds_working;
  seeds_working[0] = first_mk;
  seeds_working[1] = second_mk;

  std::array<bool, 2> t_working;
  t_working[0] = false;  // default by definition
  t_working[1] = true;   // default by definition

  auto v_working = GE2n<N>(0);

  for (uint32_t i = 0; i < term_level; ++i) {
    std::array<uint128_t, 2> seed_left;
    std::array<uint128_t, 2> seed_right;
    std::array<bool, 2> t_left;
    std::array<bool, 2> t_right;
    std::array<uint128_t, 2> v_seed_left;
    std::array<uint128_t, 2> v_seed_right;

    bool alpha_bit = (alpha.GetBit(M - i - 1) != 0U);

    // Use working seed to generate seeds
    // Note: this is the most time-consuming process
    std::tie(seed_left[0], v_seed_left[0], t_left[0], seed_right[0],
             v_seed_right[0], t_right[0]) = SplitDcfSeed(seeds_working[0]);
    std::tie(seed_left[1], v_seed_left[1], t_left[1], seed_right[1],
             v_seed_right[1], t_right[1]) = SplitDcfSeed(seeds_working[1]);

    const auto keep_seed = alpha_bit ? seed_right : seed_left;
    const auto lose_seed = alpha_bit ? seed_left : seed_right;
    const auto v_seed_keep = alpha_bit ? v_seed_right : v_seed_left;
    const auto v_seed_lose = alpha_bit ? v_seed_left : v_seed_right;
    const auto t_keep = alpha_bit ? t_right : t_left;

    bool cw_t_left;
    bool cw_t_right;
    GE2n<N> cw_v;

    uint128_t cw_seed = lose_seed[0] ^ lose_seed[1];

    // -----------------------------------------------------

    GE2n<N> prg_lose_0 = DcfPRG<N>(v_seed_lose.at(0));
    GE2n<N> prg_lose_1 = DcfPRG<N>(v_seed_lose.at(1));
    GE2n<N> prg_keep_0 = DcfPRG<N>(v_seed_keep.at(0));
    GE2n<N> prg_keep_1 = DcfPRG<N>(v_seed_keep.at(1));

    cw_v = prg_lose_1 + prg_lose_0.GetReverse() + v_working.GetReverse();

    if (t_working.at(1)) {
      cw_v.ReverseInplace();

      if (alpha_bit) {
        cw_v += beta.GetReverse();
      }

      // update v_working
      v_working += prg_keep_1.GetReverse() + prg_keep_0 + cw_v.GetReverse();

    } else {
      if (alpha_bit) {
        cw_v += beta;
      }

      // update v_working
      v_working += prg_keep_1.GetReverse() + prg_keep_0 + cw_v;
    }

    // -----------------------------------------------------

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
    first_key->cws_vec[i].SetV(cw_v.GetVal());
  }

  // Expand final seed_working
  // get the final correlation words (has the same length as seeds)
  // notice the notation is `somewhat' incorrect in the original paper
  //
  // First, we get the Convert(S_0 ^ key_block) and Convert(S_1 ^ key_block)
  //
  auto prg0 = DcfPRG<N>(seeds_working[0]);
  auto prg1 = DcfPRG<N>(seeds_working[1]);

  // if !enable_evalall, we have only one last_cw_vec, otherwise, we
  // have multiple last_cw_vec
  YACL_ENFORCE(first_key->last_cw_vec.empty());
  YACL_ENFORCE(second_key->last_cw_vec.empty());

  auto last_cw_ge2n = prg0.GetReverse() + prg1 + v_working.GetReverse();
  if (t_working[1]) {
    last_cw_ge2n.ReverseInplace();
  }

  first_key->last_cw_vec.push_back(last_cw_ge2n.GetVal());

  second_key->cws_vec = first_key->cws_vec;
  second_key->last_cw_vec.push_back(first_key->last_cw_vec[0]);
}

template <size_t /* input bit num */ M, size_t /* output bit num */ N>
void DcfEval(const DcfKey& key, const GE2n<M>& in, GE2n<N>* out) {
  uint128_t seed_working = key.GetSeed();  // the initial value
  bool t_working = key.GetRank();          // the initial value
  *out = GE2n<N>(0);                       // init the out value

  for (uint32_t i = 0; i < M; ++i) {
    const auto cw_seed = key.cws_vec[i].GetSeed();
    const GE2n<N> cw_v(key.cws_vec[i].GetV());
    const auto cw_t_left = key.cws_vec[i].GetLT();
    const auto cw_t_right = key.cws_vec[i].GetRT();

    uint128_t seed_left;
    uint128_t seed_right;
    bool t_left;
    bool t_right;
    uint128_t v_seed_left;
    uint128_t v_seed_right;

    std::tie(seed_left, v_seed_left, t_left, seed_right, v_seed_right,
             t_right) = SplitDcfSeed(seed_working);

    seed_left = t_working ? seed_left ^ cw_seed : seed_left;
    t_left = t_left ^ (t_working * cw_t_left);
    seed_right = t_working ? seed_right ^ cw_seed : seed_right;
    t_right = t_right ^ (t_working * cw_t_right);

    GE2n<N> prg0 = DcfPRG<N>(v_seed_left);
    GE2n<N> prg1 = DcfPRG<N>(v_seed_right);

    if (in.GetBit(M - i - 1) != 0U) {
      if (t_working) {
        *out += key.GetRank() ? (prg1 + cw_v).GetReverse() : prg1 + cw_v;
      } else {
        *out += key.GetRank() ? prg1.GetReverse() : prg1;
      }
      seed_working = seed_right;
      t_working = t_right;
    } else {
      if (t_working) {
        *out += key.GetRank() ? (prg0 + cw_v).GetReverse() : prg0 + cw_v;
      } else {
        *out += key.GetRank() ? prg0.GetReverse() : prg0;
      }
      seed_working = seed_left;
      t_working = t_left;
    }
  }

  auto prg = DcfPRG<N>(seed_working);
  auto tmp = t_working ? prg + GE2n<N>(key.last_cw_vec[0]) : prg;
  *out += key.GetRank() ? tmp.GetReverse() : tmp;
}

// template specification for different M and N
#define DCF_T_SPECIFY_FUNC(M, N)                                           \
  template void DcfKeyGen<M, N>(DcfKey * first_key, DcfKey * second_key,   \
                                const GE2n<M>& alpha, const GE2n<N>& beta, \
                                uint128_t first_mk, uint128_t second_mk);  \
                                                                           \
  template void DcfEval<M, N>(const DcfKey& key, const GE2n<M>& in,        \
                              GE2n<N>* out);

DCF_T_SPECIFY_FUNC(64, 64)
DCF_T_SPECIFY_FUNC(32, 64)
DCF_T_SPECIFY_FUNC(16, 64)
DCF_T_SPECIFY_FUNC(8, 64)
DCF_T_SPECIFY_FUNC(4, 64)
DCF_T_SPECIFY_FUNC(2, 64)
DCF_T_SPECIFY_FUNC(1, 64)

DCF_T_SPECIFY_FUNC(64, 128)
DCF_T_SPECIFY_FUNC(32, 128)
DCF_T_SPECIFY_FUNC(16, 128)
DCF_T_SPECIFY_FUNC(8, 128)
DCF_T_SPECIFY_FUNC(4, 128)
DCF_T_SPECIFY_FUNC(2, 128)
DCF_T_SPECIFY_FUNC(1, 128)

#undef DCF_T_SPECIFY_FUNC
}  // namespace yacl::crypto
