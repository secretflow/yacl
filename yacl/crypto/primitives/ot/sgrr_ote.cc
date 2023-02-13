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

#include "yacl/crypto/primitives/ot/sgrr_ote.h"

#include <cmath>
#include <cstring>
#include <string>
#include <vector>

#include "yacl/base/buffer.h"
#include "yacl/base/byte_container_view.h"
#include "yacl/base/dynamic_bitset.h"
#include "yacl/base/exception.h"
#include "yacl/base/int128.h"
#include "yacl/crypto/tools/prg.h"
#include "yacl/crypto/tools/random_permutation.h"

namespace yacl::crypto {

namespace {

const auto kDefaltRp =
    RandomPerm(SymmetricCrypto::CryptoType::AES128_ECB, 0x12345678);

// use one seed to generate two seeds
// we use crhash to instantiate this, see https://eprint.iacr.org/2019/074,
// section 6.2.
std::array<uint128_t, 2> SplitSeed(uint128_t seed) {
  std::array<uint128_t, 2> out;
  kDefaltRp.Gen({seed ^ 1, seed ^ 2}, absl::MakeSpan(out));
  return out;
}

}  // namespace

void SgrrOtExtRecv(const std::shared_ptr<link::Context>& ctx,
                   const OtRecvStore& base_ot, size_t n, size_t index,
                   absl::Span<uint128_t> punctured_msgs) {
  uint32_t ot_num = log2_ceil(n);
  YACL_ENFORCE_GE(n, (uint32_t)1);                         // range should > 1
  YACL_ENFORCE_GE((uint32_t)128, base_ot.choices.size());  // base ot num < 128
  YACL_ENFORCE_GE(base_ot.choices.size(), ot_num);  // base ot sanity check
  YACL_ENFORCE_GE(base_ot.blocks.size(), ot_num);   // base ot sanity check

  // we need log(n) 1-2 OTs from log(n) ROTs
  dynamic_bitset<uint128_t> choice;  // most significant bit first
  for (size_t i = 0; i < ot_num; i++) {
    choice.push_back((index >> (ot_num - i - 1)) & 1);
  }
  auto masked_choice = (~choice) ^ base_ot.choices;

  // send masked_choices to sender
  ctx->SendAsync(ctx->NextRank(), masked_choice.to_string(),
                 "SGRR_OTE:SEND-CHOICE");  // not ideal communication

  // for each level
  std::vector<uint128_t> working_seeds;
  std::vector<uint128_t> recv_msgs(2 * ot_num);
  auto recv_buf = ctx->Recv(ctx->NextRank(), "SGRR_OTE:RECV-CORR");
  std::memcpy(recv_msgs.data(), recv_buf.data(), recv_buf.size());

  for (uint32_t i = 0, empty_pos = 0; i < ot_num; i++) {
    bool ot_choice = !choice[i];
    uint32_t insert_pos = (empty_pos << 1);
    empty_pos = (empty_pos << 1) + static_cast<unsigned int>(choice[i]);

    // unmask and get the seed for this level
    uint128_t current_seed = 0;
    if (ot_choice) {
      current_seed = recv_msgs[i * 2 + 1];
    } else {
      current_seed = recv_msgs[i * 2];
    }
    current_seed ^= base_ot.blocks[i];

    // generate all already knows seeds for this level
    uint32_t iter_num = (1 << i) - 1;
    for (uint32_t j = 0; j < iter_num; j++) {
      auto split = SplitSeed(working_seeds.at(j));
      working_seeds.push_back(split[0]);
      working_seeds.push_back(split[1]);
      if (ot_choice) {
        current_seed ^= split[1];
      } else {
        current_seed ^= split[0];
      }
    }

    // delete seeds for previous level
    if (!working_seeds.empty()) {
      working_seeds.erase(working_seeds.begin(),
                          working_seeds.begin() + iter_num);
    }

    // insert the unmasked seed to the correct position
    if (insert_pos == working_seeds.size()) {
      working_seeds.push_back(current_seed);
    } else {
      working_seeds.insert(working_seeds.begin() + insert_pos, current_seed);
    }
  }

  // insert the known punctured index
  working_seeds.insert(working_seeds.begin() + static_cast<int64_t>(index), 0);
  working_seeds.resize(n);

  memcpy(punctured_msgs.data(), working_seeds.data(),
         working_seeds.size() * sizeof(uint128_t));
}

void SgrrOtExtSend(const std::shared_ptr<link::Context>& ctx,
                   const OtSendStore& base_ot, size_t n,
                   absl::Span<uint128_t> all_msgs, uint128_t seed) {
  uint32_t ot_num = log2_ceil(n);
  YACL_ENFORCE_GE(base_ot.blocks.size(), ot_num);
  YACL_ENFORCE_GE(n, (uint32_t)1);

  std::vector<uint128_t> working_seeds;
  std::vector<std::array<uint128_t, 2>> ot_msgs(ot_num);
  working_seeds.push_back(seed);

  // generate the final level seeds based on master_seed
  for (uint32_t i = 0; i < ot_num; i++) {
    //  for each seeds in level i
    uint32_t iter_num = 1 << i;
    for (uint32_t j = 0; j < iter_num; j++) {
      auto split = SplitSeed(working_seeds.at(j));
      ot_msgs[i][0] ^= split[0];
      ot_msgs[i][1] ^= split[1];
      working_seeds.push_back(split[0]);
      working_seeds.push_back(split[1]);
    }
    working_seeds.erase(working_seeds.begin(),
                        working_seeds.begin() + iter_num);
  }

  // receive the masked choices from receiver
  auto recv_buf = ctx->Recv(ctx->NextRank(), "SGRR_OTE:RECV-CHOICE");
  std::string str(static_cast<char*>(recv_buf.data()), recv_buf.size());
  dynamic_bitset<uint128_t> masked_choice(str);

  // mask the ROT messages and send back
  std::vector<uint128_t> send_msgs(2 * ot_num);
  for (uint32_t i = 0; i < ot_num; i++) {
    send_msgs[i * 2 + 0] = ot_msgs[i][0] ^ base_ot.blocks[i][masked_choice[i]];
    send_msgs[i * 2 + 1] = ot_msgs[i][1] ^ base_ot.blocks[i][!masked_choice[i]];
  }

  ctx->SendAsync(ctx->NextRank(),
                 Buffer(reinterpret_cast<const char*>(send_msgs.data()),
                        send_msgs.size() * sizeof(uint128_t)),
                 "SGRR_OTE:SEND-CORR");
  working_seeds.resize(n);

  // output the result
  memcpy(all_msgs.data(), working_seeds.data(),
         working_seeds.size() * sizeof(uint128_t));
}

}  // namespace yacl::crypto
