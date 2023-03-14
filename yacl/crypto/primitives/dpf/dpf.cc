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

#include "dpf.h"

#include <chrono>
#include <future>
#include <sstream>

#include "spdlog/spdlog.h"

#include "yacl/crypto/tools/prg.h"

#include "yacl/crypto/primitives/dpf/serializable.pb.h"

namespace yacl::crypto {

namespace {

// Get the i-th least significant bit of x
uint8_t GetBit(DpfInStore x, uint32_t i) {
  YACL_ENFORCE(i < sizeof(DpfInStore) * 8, "GetBit: index out of range");
  return x >> i & 1;
}

DpfOutStore DpfPRG(uint128_t seed) {
  Prg<uint128_t, sizeof(uint128_t)> prng(seed);
  return prng();
}

std::tuple<uint128_t, bool, uint128_t, bool> SplitDpfSeed(uint128_t seed) {
  uint128_t seed_left = 0;
  uint128_t seed_right = 0;
  bool t_left;
  bool t_right;

  // TODO: check if this implementation is secure and efficient
  Prg<uint128_t, 3 * sizeof(uint128_t)> prng(seed);

  seed_left = prng();
  seed_right = prng();

  uint128_t tmp = prng();

  t_left = tmp >> 1 & 1;
  t_right = tmp >> 2 & 1;

  return {seed_left, t_left, seed_right, t_right};
}

}  // namespace

/////////////////////////////////////////////////////////////////////////////////////
// Full domain key generation and evaluation
/////////////////////////////////////////////////////////////////////////////////////

void DpfContext::Gen(DpfKey& first_key, DpfKey& second_key, DpfInStore alpha,
                     DpfOutStore beta, uint128_t first_mk, uint128_t second_mk,
                     bool enable_evalall) {
  YACL_ENFORCE(this->in_bitnum_ > 0);
  YACL_ENFORCE(this->in_bitnum_ > log(alpha));
  YACL_ENFORCE(this->in_bitnum_ < 64);
  YACL_ENFORCE(this->ss_bitnum_ > 0);
  YACL_ENFORCE(this->ss_bitnum_ <= 64);

  // enable the early termination
  uint32_t term_level = GetTerminateLevel(enable_evalall);

  // set up the return keys
  first_key = DpfKey(false, GetInBitNum(), GetSsBitNum(), sec_param_, first_mk);
  second_key =
      DpfKey(true, GetInBitNum(), GetSsBitNum(), sec_param_, second_mk);
  first_key.cws_vec.resize(term_level);
  second_key.cws_vec.resize(term_level);

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

    bool alpha_bit = (GetBit(alpha, i) != 0U);

    // Use working seed to generate seeds
    // Note: this is the most time-consuming process
    // [TODO]: Make this parallel
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

    first_key.cws_vec[i].SetSeed(cw_seed);
    first_key.cws_vec[i].SetTLeft(cw_t_left);
    first_key.cws_vec[i].SetTRight(cw_t_right);
  }

  // Expand final seed_working
  // get the final correlation words (has the same length as seeds)
  // notice the notation is `somewhat' incorrect in the original paper
  //
  // First, we get the Convert(S_0 ^ key_block) and Convert(S_1 ^ key_block)
  //
  DpfOutStore prg0 = DpfPRG(seeds_working[0]);
  DpfOutStore prg1 = DpfPRG(seeds_working[1]);

  // if enable_evalall, we have only one last_cw_vec, otherwise, we
  // have multiple last_cw_vec
  YACL_ENFORCE(first_key.last_cw_vec.empty());
  YACL_ENFORCE(second_key.last_cw_vec.empty());

  if (!enable_evalall) {
    first_key.last_cw_vec.push_back(TruncateSs(beta + ReverseSs(prg0) + prg1));
    if (t_working[1]) {
      first_key.last_cw_vec[0] = ReverseSs(first_key.last_cw_vec[0]);
    }
    second_key.cws_vec = first_key.cws_vec;
    second_key.last_cw_vec.push_back(first_key.last_cw_vec[0]);
  } else {
    first_key.EnableEvalAll();
    second_key.EnableEvalAll();

    uint32_t alpha_pos_term_level = alpha >> term_level;
    uint32_t expand_num = static_cast<uint32_t>(1)
                          << (GetInBitNum() - term_level);

    for (uint32_t i = 0; i < expand_num; i++) {
      DpfOutStore last_cw = 0;
      if (i == alpha_pos_term_level) {
        last_cw = TruncateSs(beta + ReverseSs(prg0) + TruncateSs(prg1));
      } else {
        last_cw = TruncateSs(ReverseSs(prg0) + TruncateSs(prg1));
      }

      if (t_working[1]) {
        first_key.last_cw_vec.push_back(ReverseSs(last_cw));
      } else {
        first_key.last_cw_vec.push_back(last_cw);
      }

      second_key.cws_vec = first_key.cws_vec;
      second_key.last_cw_vec.push_back(first_key.last_cw_vec[i]);

      prg0 = DpfPRG(prg0);
      prg1 = DpfPRG(prg1);
    }
  }
  // return {std::move(first_key), std::move(second_key)};
}  // namespace flcrypto

DpfOutStore DpfContext::Eval(DpfKey& key, DpfInStore x) {
  YACL_ENFORCE(this->in_bitnum_ > log(x));
  YACL_ENFORCE(key.enable_evalall == false);

  uint128_t seed_working = key.GetSeed();  // the initial value
  bool t_working = key.GetRank();          // the initial value

  for (uint32_t i = 0; i < GetInBitNum(); i++) {
    const auto cw_seed = key.cws_vec[i].GetSeed();
    const auto cw_t_left = key.cws_vec[i].GetTLeft();
    const auto cw_t_right = key.cws_vec[i].GetTRight();

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

    if (GetBit(x, i) != 0U) {
      seed_working = seed_right;
      t_working = t_right;
    } else {
      seed_working = seed_left;
      t_working = t_left;
    }
  }

  DpfOutStore prg = TruncateSs(DpfPRG(seed_working));

  DpfOutStore result = key.GetRank()
                           ? ReverseSs(prg + t_working * key.last_cw_vec[0])
                           : TruncateSs(prg + t_working * key.last_cw_vec[0]);

  return TruncateSs(result);
}

void DpfContext::Traverse(DpfKey& key, std::vector<DpfOutStore>& result,
                          size_t current_level, uint64_t current_pos,
                          uint128_t seed_working, bool t_working,
                          size_t term_level) {
  if (current_level < term_level) {
    uint128_t seed_left;
    uint128_t seed_right;
    bool t_left;
    bool t_right;
    const auto cw_seed = key.cws_vec[current_level].GetSeed();
    const auto cw_t_left = key.cws_vec[current_level].GetTLeft();
    const auto cw_t_right = key.cws_vec[current_level].GetTRight();

    std::tie(seed_left, t_left, seed_right, t_right) =
        SplitDpfSeed(seed_working);

    seed_left = t_working ? seed_left ^ cw_seed : seed_left;
    t_left = t_left ^ (t_working * cw_t_left);
    seed_right = t_working ? seed_right ^ cw_seed : seed_right;
    t_right = t_right ^ (t_working * cw_t_right);

    uint64_t next_left_pos = current_pos;
    uint64_t next_right_pos = (1ULL << current_level) + current_pos;

    Traverse(key, result, current_level + 1, next_left_pos, seed_left, t_left,
             term_level);
    Traverse(key, result, current_level + 1, next_right_pos, seed_right,
             t_right, term_level);

  } else {
    DpfOutStore prg = DpfPRG(seed_working);
    uint32_t expand_num = static_cast<uint32_t>(1)
                          << (GetInBitNum() - term_level);

    for (uint32_t i = 0; i < expand_num; i++) {
      result[current_pos + (i << term_level)] =
          key.GetRank()
              ? ReverseSs(TruncateSs(prg) + t_working * key.last_cw_vec[i])
              : TruncateSs(TruncateSs(prg) + t_working * key.last_cw_vec[i]);
      prg = DpfPRG(prg);
    }
  }
}

std::vector<DpfOutStore> DpfContext::EvalAll(DpfKey& key) {
  YACL_ENFORCE(key.enable_evalall == true);

  uint128_t seed_working = key.GetSeed();  // the initial value
  bool t_working = key.GetRank();          // the initial value
  uint32_t term_level = GetTerminateLevel(true);

  YACL_ENFORCE(GetInBitNum() <= 25);  // only support in_bin_num < 25

  uint64_t num = 1ULL << GetInBitNum();
  std::vector<DpfOutStore> result(num);

  uint64_t current_pos = 0;
  uint64_t current_level = 0;  // we start from the top level

  Traverse(key, result, current_level, current_pos, seed_working, t_working,
           term_level);

  return result;
}

std::string DpfKey::Serialize() const {
  DpfKeyProto proto;
  // Set properties
  proto.set_enable_evalall(enable_evalall);
  for (const auto& cws : cws_vec) {
    auto* cws_proto = proto.add_cws_vec();
    auto i128_parts = DecomposeUInt128(cws.GetSeed());
    cws_proto->mutable_seed()->set_hi(i128_parts.first);
    cws_proto->mutable_seed()->set_lo(i128_parts.second);
    cws_proto->set_t_store(cws.GetTStore());
  }
  for (const auto& last_cw : last_cw_vec) {
    auto* last_cw_proto = proto.add_last_cw_vec();
    auto i128_parts = DecomposeUInt128(last_cw);
    last_cw_proto->set_hi(i128_parts.first);
    last_cw_proto->set_lo(i128_parts.second);
  }
  proto.set_rank(rank_);
  proto.set_in_bitnum(in_bitnum_);
  proto.set_ss_bitnum(ss_bitnum_);
  proto.set_sec_param(sec_param_);

  auto i128_parts = DecomposeUInt128(mseed_);
  proto.mutable_mseed()->set_hi(i128_parts.first);
  proto.mutable_mseed()->set_lo(i128_parts.second);

  return proto.SerializeAsString();
}

void DpfKey::Deserialize(const std::string& s) {
  DpfKeyProto proto;
  proto.ParseFromString(s);

  enable_evalall = proto.enable_evalall();
  cws_vec.clear();
  for (const auto& cws_proto : proto.cws_vec()) {
    cws_vec.emplace_back(
        MakeUint128(cws_proto.seed().hi(), cws_proto.seed().lo()),
        cws_proto.t_store());
  }

  last_cw_vec.clear();
  for (const auto& last_cw_proto : proto.last_cw_vec()) {
    last_cw_vec.emplace_back(
        MakeUint128(last_cw_proto.hi(), last_cw_proto.lo()));
  }

  rank_ = proto.rank();
  in_bitnum_ = proto.in_bitnum();
  ss_bitnum_ = proto.ss_bitnum();
  sec_param_ = proto.sec_param();

  mseed_ = MakeUint128(proto.mseed().hi(), proto.mseed().lo());
}

}  // namespace yacl::crypto
