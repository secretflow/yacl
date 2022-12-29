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

#include <math.h>

#include "yacl/base/byte_container_view.h"
#include "yacl/base/exception.h"
#include "yacl/crypto/tools/prg.h"

namespace yacl::crypto {

namespace {

#define LOG2(X) \
  ((unsigned)(8 * sizeof(unsigned long long) - __builtin_clzll((X)) - 1))

// use one seed to generate two seeds
std::pair<uint128_t, uint128_t> SplitSeed(uint128_t seed) {
  Prg<uint128_t> prg(seed);
  return {prg(), prg()};
}

// 1st 4 bytes: the length of vector<bool>
// other bytes: contents of vector<bool> (padding with 0s)
inline std::vector<uint8_t> BufferFromVectorBool(
    const std::vector<bool>& vector) {
  YACL_ENFORCE_GT(sizeof(uint32_t) * 16, vector.size());
  YACL_ENFORCE_GT(vector.size(), (uint32_t)1);

  uint32_t size = vector.size();
  std::vector<uint8_t> buf(((size - 1) / 8) + 5);
  memcpy(buf.data(), &size, sizeof(uint32_t));

  auto* out = buf.data() + 4;
  int shift = 0;
  for (bool bit : vector) {
    *out |= bit << shift;
    if (++shift == 8) {
      ++out;
      shift = 0;
    }
  }
  return buf;
}

// convert a string to std::vector<bool>
inline std::vector<bool> VectorBoolFromBuffer(const Buffer& str) {
  uint32_t ret_size = 0;
  memcpy(&ret_size, str.data<char>(), sizeof(uint32_t));
  std::vector<bool> ret(ret_size, false);
  uint32_t str_counter = 0;
  for (uint32_t i = 4; i < str.size(); i++) {
    uint8_t temp = str.data<char>()[i];
    for (uint32_t j = 0; j < 8 && str_counter < ret_size; j++) {
      ret[str_counter] = temp & 1;
      temp >>= 1;
      str_counter++;
    }
  }
  return ret;
}

}  // namespace

void SgrrOtExtRecv(const std::shared_ptr<link::Context>& ctx,
                   const BaseOtRecvStore& ot_options, uint32_t n,
                   uint32_t index, absl::Span<uint128_t> punctured_seeds) {
  uint32_t ot_num = LOG2(n);
  YACL_ENFORCE_GT(n, (uint32_t)1);
  YACL_ENFORCE_GE(ot_options.choices.size(), ot_num);
  YACL_ENFORCE_GE(ot_options.blocks.size(), ot_num);

  std::vector<bool> choices(ot_num);  // most significant bit first
  for (uint32_t i = 0; i < ot_num; i++) {
    choices[ot_num - i - 1] = (index >> i & 1);
  }

  // we need log(n) 1-2 OTs from log(n) ROTs
  {
    std::vector<bool> masked_choices(ot_num);
    for (uint32_t i = 0; i < ot_num; i++) {
      masked_choices[i] = (!choices[i]) ^ ot_options.choices[i];
    }
    // send masked_choices to sender
    ctx->SendAsync(ctx->NextRank(), BufferFromVectorBool(masked_choices),
                   fmt::format("PUNC_ROT:SEND:{}", 0));
  }

  std::vector<uint128_t> temp_seed_vec;
  for (uint32_t i = 0, empty_pos = 0; i < ot_num; i++) {
    bool ot_choice = !choices.at(i);
    uint32_t insert_pos = (empty_pos << 1);
    empty_pos = (empty_pos << 1) + choices[i];

    // unmask and get the seed for this level
    uint128_t current_seed = 0;
    {
      auto recv_string =
          ctx->Recv(ctx->NextRank(), fmt::format("PUNC_ROT:RECV:{}", i + 1));
      if (ot_choice) {
        std::memcpy(&current_seed, recv_string.data<char>() + sizeof(uint128_t),
                    sizeof(uint128_t));
      } else {
        std::memcpy(&current_seed, recv_string.data<char>(), sizeof(uint128_t));
      }
      current_seed ^= ot_options.blocks[i];
    }

    // generate all already knows seeds for this level
    uint32_t iter_num = (1 << i) - 1;
    for (uint32_t j = 0; j < iter_num; j++) {
      uint128_t left = 0;
      uint128_t right = 0;
      YACL_ENFORCE(!temp_seed_vec.empty());
      std::tie(left, right) = SplitSeed(temp_seed_vec.at(j));
      temp_seed_vec.push_back(left);
      temp_seed_vec.push_back(right);
      if (ot_choice) {
        current_seed ^= right;
      } else {
        current_seed ^= left;
      }
    }

    // delete seeds for previous level
    if (!temp_seed_vec.empty()) {
      temp_seed_vec.erase(temp_seed_vec.begin(),
                          temp_seed_vec.begin() + iter_num);
    }

    // insert the unmasked seed to the correct position
    if (insert_pos == temp_seed_vec.size()) {
      temp_seed_vec.push_back(current_seed);
    } else {
      temp_seed_vec.insert(temp_seed_vec.begin() + insert_pos, current_seed);
    }
  }

  memcpy(punctured_seeds.data(), temp_seed_vec.data(),
         temp_seed_vec.size() * sizeof(uint128_t));
}

void SgrrOtExtSend(const std::shared_ptr<link::Context>& ctx,
                   const BaseOtSendStore& ot_options, uint32_t n,
                   uint128_t master_seed, absl::Span<uint128_t> entire_seeds) {
  uint32_t ot_num = LOG2(n);
  YACL_ENFORCE_GE(ot_options.blocks.size(), ot_num);
  YACL_ENFORCE_GT(n, (uint32_t)1);

  std::vector<uint128_t> temp_seed_vec;
  std::vector<std::array<uint128_t, 2>> ot_message_vec(ot_num);
  temp_seed_vec.push_back(master_seed);

  // generate the final level seeds based on master_seed
  for (uint32_t i = 0; i < ot_num; i++) {
    //  for each seeds in level i
    uint32_t iter_num = 1 << i;
    for (uint32_t j = 0; j < iter_num; j++) {
      uint128_t left = 0;
      uint128_t right = 0;
      std::tie(left, right) = SplitSeed(temp_seed_vec.at(j));
      ot_message_vec[i][0] ^= left;
      ot_message_vec[i][1] ^= right;
      temp_seed_vec.push_back(left);
      temp_seed_vec.push_back(right);
    }
    temp_seed_vec.erase(temp_seed_vec.begin(),
                        temp_seed_vec.begin() + iter_num);
  }

  // receive the masked choices from receiver
  auto recv_string =
      ctx->Recv(ctx->NextRank(), fmt::format("PUNC_ROT:RECV:{}", 0));
  std::vector<bool> masked_choices = VectorBoolFromBuffer(recv_string);

  // mask the ROT messages and send back
  for (uint32_t i = 0; i < ot_num; i++) {
    std::array<uint128_t, 2> send_message;
    send_message[0] =
        ot_message_vec[i][0] ^ ot_options.blocks[i][masked_choices[i]];
    send_message[1] =
        ot_message_vec[i][1] ^ ot_options.blocks[i][1 - masked_choices[i]];

    auto buf =
        ByteContainerView{reinterpret_cast<const char*>(send_message.data()),
                          send_message.size() * sizeof(uint128_t)};
    ctx->SendAsync(ctx->NextRank(), buf,
                   fmt::format("PUNC_ROT:SEND:{}", i + 1));
  }

  // output the result
  memcpy(entire_seeds.data(), temp_seed_vec.data(),
         temp_seed_vec.size() * sizeof(uint128_t));
}

}  // namespace yacl::crypto
