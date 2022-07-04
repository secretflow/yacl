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


#include "yasl/mpctools/ot/punctured_rand_ot.h"

#include <math.h>

#include "yasl/base/byte_container_view.h"
#include "yasl/base/exception.h"
#include "yasl/crypto/pseudo_random_generator.h"

// #include <bitset>

namespace yasl {

namespace {

// use one seed to generate two seeds
std::pair<PuncturedOTSeed, PuncturedOTSeed> SplitSeed(PuncturedOTSeed seed) {
  // pre-fetch 2 128-bit randomness
  PseudoRandomGenerator<PuncturedOTSeed, sizeof(PuncturedOTSeed) * 8> prg(seed);
  return {prg(), prg()};
}

// 1st 4 bytes: the length of vector<bool>
// other bytes: contents of vector<bool> (padding with 0s)
inline Buffer BufferFromVectorBool(const std::vector<bool>& vector) {
  YASL_ENFORCE_GT(sizeof(uint32_t) * 16, vector.size());
  YASL_ENFORCE_GT(vector.size(), (uint32_t)1);

  uint32_t size = vector.size();
  Buffer buf(((size - 1) / 8) + 5);
  memcpy(buf.data(), &size, sizeof(uint32_t));

  auto* out = buf.data<char>() + 4;
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
  std::vector<bool> ret(ret_size, 0);
  uint32_t str_counter = 0;
  for (uint32_t i = 4; i < str.size(); i++) {
    uint8_t temp = str.data<char>()[i];
    for (uint32_t j = 0; j < 8 && str_counter < ret_size; j++) {
      ret.at(str_counter) = temp & 1;
      temp >>= 1;
      str_counter++;
    }
  }
  return ret;
}

}  // namespace

void PuncturedROTRecv(const std::shared_ptr<link::Context>& ctx,
                      const OTRecvOptions& ot_options, uint32_t n,
                      uint32_t index,
                      absl::Span<PuncturedOTSeed> punctured_seeds) {
  uint32_t ot_num = log2(n);
  YASL_ENFORCE_GT(n, (uint32_t)1);
  YASL_ENFORCE_GE(ot_options.choices.size(), ot_num);
  YASL_ENFORCE_GE(ot_options.blocks.size(), ot_num);

  std::vector<bool> choices(ot_num);  // most significant bit first
  for (uint32_t i = 0; i < ot_num; i++) {
    choices.at(ot_num - i - 1) = (index >> i & 1);
  }

  // we need log(n) 1-2 OTs from log(n) ROTs
  {
    std::vector<bool> masked_choices(ot_num);
    for (uint32_t i = 0; i < ot_num; i++) {
      masked_choices.at(i) = (!choices.at(i)) ^ ot_options.choices.at(i);
    }
    // send masked_choices to sender
    ctx->SendAsync(ctx->NextRank(), BufferFromVectorBool(masked_choices),
                   fmt::format("PUNC_ROT:SEND:{}", 0));
  }

  std::vector<PuncturedOTSeed> temp_seed_vec;
  for (uint32_t i = 0, empty_pos = 0; i < ot_num; i++) {
    bool ot_choice = !choices.at(i);
    uint32_t insert_pos = (empty_pos << 1);
    empty_pos = (empty_pos << 1) + choices.at(i);

    // unmask and get the seed for this level
    PuncturedOTSeed current_seed;
    {
      auto recv_string =
          ctx->Recv(ctx->NextRank(), fmt::format("PUNC_ROT:RECV:{}", i + 1));
      std::memcpy(
          &current_seed,
          recv_string.data<char>() + ot_choice * sizeof(PuncturedOTSeed),
          sizeof(PuncturedOTSeed));
      current_seed ^= ot_options.blocks.at(i);
    }

    // generate all already knows seeds for this level
    uint32_t iter_num = pow(2, i) - 1;
    for (uint32_t j = 0; j < iter_num; j++) {
      PuncturedOTSeed left, right;
      YASL_ENFORCE_EQ(temp_seed_vec.empty(), 0);
      std::tie(left, right) = SplitSeed(temp_seed_vec.at(j));
      temp_seed_vec.push_back(left);
      temp_seed_vec.push_back(right);
      current_seed ^= ot_choice * right + (1 - ot_choice) * left;
    }

    // delete seeds for previous level
    if (!temp_seed_vec.empty())
      temp_seed_vec.erase(temp_seed_vec.begin(),
                          temp_seed_vec.begin() + iter_num);

    // insert the unmasked seed to the correct position
    if (insert_pos == temp_seed_vec.size())
      temp_seed_vec.push_back(current_seed);
    else
      temp_seed_vec.insert(temp_seed_vec.begin() + insert_pos, current_seed);
  }

  memcpy(punctured_seeds.data(), temp_seed_vec.data(),
         temp_seed_vec.size() * sizeof(PuncturedOTSeed));
}

void PuncturedROTSend(const std::shared_ptr<link::Context>& ctx,
                      const OTSendOptions& ot_options, uint32_t n,
                      PuncturedOTSeed master_seed,
                      absl::Span<PuncturedOTSeed> entire_seeds) {
  uint32_t ot_num = log2(n);
  YASL_ENFORCE_GE(ot_options.blocks.size(), ot_num);
  YASL_ENFORCE_GT(n, (uint32_t)1);

  std::vector<PuncturedOTSeed> temp_seed_vec;
  std::vector<std::array<PuncturedOTSeed, 2>> ot_message_vec(ot_num);
  temp_seed_vec.push_back(master_seed);

  // generate the final level seeds based on master_seed
  for (uint32_t i = 0; i < ot_num; i++) {
    //  for each seeds in level i
    uint32_t iter_num = pow(2, i);
    for (uint32_t j = 0; j < iter_num; j++) {
      PuncturedOTSeed left, right;
      std::tie(left, right) = SplitSeed(temp_seed_vec.at(j));
      ot_message_vec.at(i).at(0) ^= left;
      ot_message_vec.at(i).at(1) ^= right;
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
    std::array<PuncturedOTSeed, 2> send_message;
    send_message.at(0) = ot_message_vec.at(i).at(0) ^
                         ot_options.blocks.at(i).at(masked_choices.at(i));
    send_message.at(1) = ot_message_vec.at(i).at(1) ^
                         ot_options.blocks.at(i).at(1 - masked_choices.at(i));
    ctx->SendAsync(
        ctx->NextRank(),
        ByteContainerView{reinterpret_cast<const char*>(send_message.data()),
                          send_message.size() * sizeof(PuncturedOTSeed)},
        fmt::format("PUNC_ROT:SEND:{}", i + 1));
  }

  // output the result
  memcpy(entire_seeds.data(), temp_seed_vec.data(),
         temp_seed_vec.size() * sizeof(PuncturedOTSeed));
}

}  // namespace yasl