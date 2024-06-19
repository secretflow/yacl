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

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <random>
#include <string>
#include <thread>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

#include "yacl/base/exception.h"
#include "yacl/base/int128.h"

/* submodules */
#include "yacl/crypto/tools/prg.h"

namespace yacl::crypto {

// Implementation of Distributed Point Function (DPF)
// title : Function Secret Sharing: Improvements and Extensions
// eprint: https://eprint.iacr.org/2018/707
//
// Assume we have a function F(*), where F(alpha)=beta, F(*!=alpha)=0.
// DPF splits the finction into two parts F1 and F2, and ensures F1(alpha)=r,
// F2(alpha)=-r+beta, and F1(*!=alpha)=r, F2(*!=alpha)=-r
//
// alpha : arbitrary length mapping input
// beta  : 128bit mapping output
// Note: result is A-share

using DpfInStore = uint128_t;   // the input room
using DpfOutStore = uint128_t;  // the secret sharing room

struct DpfCW {
 public:
  DpfCW() = default;
  DpfCW(uint128_t seed, uint8_t t_store) : seed_(seed), t_store_(t_store) {}

  bool GetTLeft() const { return t_store_ & 1; }
  bool GetTRight() const { return (t_store_ >> 1) & 1; }

  uint128_t GetSeed() const { return seed_; }
  uint8_t GetTStore() const { return t_store_; }

  void SetTLeft(bool t_left) { t_store_ = (GetTRight() << 1) + t_left; }
  void SetTRight(bool t_right) { t_store_ = (t_right << 1) + GetTLeft(); }
  void SetSeed(uint128_t seed) { seed_ = seed; }

 private:
  uint128_t seed_ = 0;   // this level's seed, default = 0
  uint8_t t_store_ = 0;  // 1st bit=> t_left, 2nd bit=> t_right
};

class DpfKey {
 public:
  bool enable_evalall = false;           // full domain eval
  std::vector<DpfCW> cws_vec;            // correlated words for each level
  std::vector<DpfOutStore> last_cw_vec;  // the final correlation word

  // empty constructor
  DpfKey() = default;

  DpfKey(bool rank, const uint128_t mseed) : rank_(rank), mseed_(mseed) {}

  DpfKey(bool rank, size_t in_bitnum, size_t ss_bitnum, uint32_t sec_param,
         const uint128_t mseed)
      : rank_(rank),
        in_bitnum_(in_bitnum),
        ss_bitnum_(ss_bitnum),
        sec_param_(sec_param),
        mseed_(mseed) {}

  void EnableEvalAll() { enable_evalall = true; }
  void DisableFullEval() { enable_evalall = false; }

  bool GetRank() const { return rank_; }
  void SetRank(bool rank) { rank_ = rank; }

  uint128_t GetSeed() const { return mseed_; }
  void SetSeed(uint128_t seed) { mseed_ = seed; }

  size_t GetInBitNum() const { return in_bitnum_; }
  size_t GetSsBitNum() const { return ss_bitnum_; }

  uint32_t GetSecParam() const { return sec_param_; }

  Buffer Serialize() const;
  void Deserialize(ByteContainerView s);

 private:
  bool rank_{};            // only support two parties (0/1), compulsory param
  size_t in_bitnum_ = 64;  // bit number (for point), default = 64
  size_t ss_bitnum_ = 64;  // bit number (for output value), default = 64
  uint32_t sec_param_ = 128;  // we assume 128 bit security (fixed)
  uint128_t mseed_ = 0;       // the master seed (the default is not secure)
};

class DpfContext {
 public:
  // constructors
  DpfContext() = default;

  explicit DpfContext(size_t in_bitnum) : in_bitnum_(in_bitnum) {}

  DpfContext(size_t in_bitnum, size_t ss_bitnum)
      : in_bitnum_(in_bitnum), ss_bitnum_(ss_bitnum) {}

  void SetInBitNum(size_t in_bitnum) {
    YACL_ENFORCE(in_bitnum <= 64);
    in_bitnum_ = in_bitnum;
  }
  size_t GetInBitNum() const { return in_bitnum_; }

  void SetSsBitNum(size_t ss_bitnum) {
    YACL_ENFORCE(ss_bitnum <= 64);
    ss_bitnum_ = ss_bitnum;
  }
  size_t GetSsBitNum() const { return ss_bitnum_; }

  // --------------------------------------
  // Original key generation and evaluation
  // --------------------------------------
  std::pair<DpfKey, DpfKey> Gen(DpfInStore alpha, DpfOutStore beta,
                                uint128_t first_mk, uint128_t second_mk,
                                bool enable_evalall = false) {
    DpfKey k0;
    DpfKey k1;
    Gen(k0, k1, alpha, beta, first_mk, second_mk, enable_evalall);
    return {std::move(k0), std::move(k1)};
  }

  void Gen(DpfKey& first_key, DpfKey& second_key, DpfInStore alpha,
           DpfOutStore beta, uint128_t first_mk, uint128_t second_mk,
           bool enable_evalall = false);

  DpfOutStore Eval(DpfKey& key, DpfInStore input);

  std::vector<DpfOutStore> EvalAll(DpfKey& key);

  DpfOutStore GetSsMask() const {
    YACL_ENFORCE(ss_bitnum_ <= 64);
    if (ss_bitnum_ == 64) {
      return 0xFFFFFFFFFFFFFFFF;
    }
    return (static_cast<uint64_t>(1) << ss_bitnum_) - 1;
  }

  DpfOutStore TruncateSs(DpfOutStore input) const {
    YACL_ENFORCE(ss_bitnum_ <= 64);
    return input & GetSsMask();
  }

  DpfOutStore ReverseSs(DpfOutStore input) const {
    YACL_ENFORCE(ss_bitnum_ <= 64);
    return TruncateSs(GetSsMask() - TruncateSs(input) + 1);
  }

 private:
  void Traverse(DpfKey& key, std::vector<DpfOutStore>& result,
                size_t current_level, uint64_t current_pos,
                uint128_t seed_working, bool t_working, size_t term_level);

  // Note that for the case of sec_param = 128 and ss_bitnum = 64, we
  // always have term_level = in_bitnum
  size_t GetTerminateLevel(bool enable_evalall) const {
    if (!enable_evalall) {
      return in_bitnum_;
    }
    size_t n = in_bitnum_;
    size_t x = ceil(n - log(sec_param_ / ss_bitnum_));
    return std::min(n, x);
  }

  size_t in_bitnum_ = 64;
  size_t ss_bitnum_ = 64;
  uint32_t sec_param_ = 128;  // we assume 128 bit security (fixed)
};
}  // namespace yacl::crypto
