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

#include <algorithm>
#include <cmath>
#include <cstring>
#include <string>
#include <vector>

#include "yacl/base/buffer.h"
#include "yacl/base/byte_container_view.h"
#include "yacl/base/dynamic_bitset.h"
#include "yacl/base/exception.h"
#include "yacl/base/int128.h"
#include "yacl/crypto/base/aes/aes_opt.h"
#include "yacl/crypto/tools/prg.h"
#include "yacl/crypto/tools/random_permutation.h"
#include "yacl/crypto/utils/math.h"
#include "yacl/crypto/utils/rand.h"

namespace yacl::crypto {

namespace {

const std::array<AES_KEY, 2> kPrfKey = {AES_set_encrypt_key(0),
                                        AES_set_encrypt_key(1)};  // fixed key

// use one seed to generate two seeds
// we use crhash to instantiate this, see https://eprint.iacr.org/2019/074,
// section 6.2.(a.k.a. CrHash = Rp(x) ^ x)
// That is: G(seed) = Rp(key, seed^1) ^ seed^1 || Rp(key, seed^2) ^ seed^2
//
// However, we can further optimize the procedure using two-key PRF with AES key
// scheduling, that is: G(seed) = Rp(key1, seed) ^ seed || Rp(key2, seed) ^ seed
// see:
// https://github.com/emp-toolkit/emp-ot/blob/master/emp-ot/ferret/twokeyprp.h
//

// std::array<uint128_t, 2> SplitSeed(const std::array<AES_KEY, 2>& keys,
//                                    uint128_t seed) {
//   std::array<uint128_t, 2> tmp = {seed, seed};
//   // Uncomment the following if you want to use CrHash:
//   // kDefaltRp.Gen({seed ^ 1, seed ^ 2}, absl::MakeSpan(tmp));

//   // Use two-key prf
//   ParaEnc<2, 1>(tmp.data(), keys.data());
//   return {tmp[0] ^ seed, tmp[1] ^ seed};
// }

inline dynamic_bitset<uint128_t> MakeDynamicBitset(uint128_t input,
                                                   size_t bits) {
  dynamic_bitset<uint128_t> out;
  out.append(input);
  out.resize(bits);
  YACL_ENFORCE(out.num_blocks() == 1);
  return out;
}

inline uint128_t GetPuncturedIndex(const dynamic_bitset<uint128_t>& choice,
                                   uint32_t level) {
  dynamic_bitset<uint128_t> punctured_set = choice;
  punctured_set.resize(level + 1);
  return *static_cast<uint128_t*>(punctured_set.data());
}

inline uint128_t GetInsertedIndex(const dynamic_bitset<uint128_t>& choice,
                                  uint32_t level) {
  dynamic_bitset<uint128_t> inserted_set = choice;
  inserted_set.resize(level + 1);
  inserted_set.flip(level);
  return *static_cast<uint128_t*>(inserted_set.data());
}

std::vector<uint128_t> SplitAllSeeds(absl::Span<uint128_t> seeds) {
  // Use two-key prf in a faster way
  const size_t split_num = seeds.size();
  std::vector<uint128_t> out(split_num * 2);
  std::memcpy(out.data(), seeds.data(), split_num * sizeof(uint128_t));
  std::memcpy(out.data() + split_num, seeds.data(),
              split_num * sizeof(uint128_t));
  ParaEnc<2>(out.data(), kPrfKey.data(), split_num);

  return out;
}

}  // namespace

void SgrrOtExtRecv(const std::shared_ptr<link::Context>& ctx,
                   const std::shared_ptr<OtRecvStore>& base_ot, uint32_t n,
                   uint32_t index, absl::Span<uint128_t> output) {
  uint32_t ot_num = Log2Ceil(n);
  YACL_ENFORCE_GE(n, (uint32_t)1);                  // range should > 1
  YACL_ENFORCE_GE((uint32_t)128, base_ot->Size());  // base ot num < 128
  YACL_ENFORCE_GE(base_ot->Size(), ot_num);         //

  // we need log(n) 1-2 OTs from log(n) ROTs
  // most significant bit first
  dynamic_bitset<uint128_t> choice = MakeDynamicBitset(index, ot_num);
  dynamic_bitset<uint128_t> masked_choice = ~choice;
  for (uint64_t i = 0; i < ot_num; ++i) {
    masked_choice[i] ^= base_ot->GetChoice(i);
  }

  // send masked_choices to sender
  ctx->SendAsync(
      ctx->NextRank(),
      ByteContainerView(masked_choice.data(),
                        masked_choice.num_blocks() * sizeof(uint128_t)),
      "SGRR_OTE:SEND-CHOICE");

  // receive masked messages from sender
  std::vector<std::array<uint128_t, 2>> recv_msgs(ot_num);
  auto recv_buf = ctx->Recv(ctx->NextRank(), "SGRR_OTE:RECV-CORR");
  std::memcpy(recv_msgs.data(), recv_buf.data(), recv_buf.size());

  // for each level
  for (uint32_t i = 0; i < ot_num; ++i) {
    auto punctured_idx = GetPuncturedIndex(choice, i);
    auto inserted_idx = GetInsertedIndex(choice, i);

    // unmask and get the seed for this level
    uint128_t insert_val = recv_msgs[i][1 - choice[i]] ^ base_ot->GetBlock(i);

    // generate all already knows seeds for this level
    if (i != 0) {
      const uint32_t iter_num = 1 << i;
      auto splits = SplitAllSeeds(output.subspan(0, iter_num));
      for (uint32_t j = 0; j < std::min(iter_num, n); ++j) {
        if (j == punctured_idx || j == inserted_idx) {
          continue;
        }
        splits[j] ^= output[j];
        splits[j + iter_num] ^= output[j];
        insert_val ^= choice[i] ? splits[j] : splits[j + iter_num];
      }
      memcpy(output.data(), splits.data(),
             std::min(2 * iter_num, n) * sizeof(uint128_t));
    }
    output[punctured_idx] = 0;
    if (inserted_idx < n) {
      output[inserted_idx] = insert_val;
    }
  }
}

void SgrrOtExtSend(const std::shared_ptr<link::Context>& ctx,
                   const std::shared_ptr<OtSendStore>& base_ot, uint32_t n,
                   absl::Span<uint128_t> output) {
  uint32_t ot_num = Log2Ceil(n);
  YACL_ENFORCE_GE(base_ot->Size(), ot_num);
  YACL_ENFORCE_GE(n, (uint32_t)1);

  std::vector<std::array<uint128_t, 2>> send_msgs(ot_num);
  output[0] = SecureRandSeed();

  // generate the final level seeds based on master_seed
  for (uint32_t i = 0; i < ot_num; ++i) {
    //  for each seeds in level i
    const uint32_t iter_num = 1 << i;
    auto splits = SplitAllSeeds(output.subspan(0, iter_num));
    for (uint32_t j = 0; j < std::min(iter_num, n); ++j) {
      splits[j] ^= output[j];
      splits[j + iter_num] ^= output[j];
      send_msgs[i][0] ^= splits[j];             // left
      send_msgs[i][1] ^= splits[j + iter_num];  // right
    }
    memcpy(output.data(), splits.data(),
           std::min(2 * iter_num, n) * sizeof(uint128_t));
  }

  // receive the masked choices from receiver
  dynamic_bitset<uint128_t> masked_choice(ot_num);
  auto recv_buf = ctx->Recv(ctx->NextRank(), "SGRR_OTE:RECV-CHOICE");
  memcpy(masked_choice.data(), recv_buf.data(),
         masked_choice.num_blocks() * sizeof(uint128_t));

  // mask the ROT messages and send back
  for (uint32_t i = 0; i < ot_num; ++i) {
    send_msgs[i][0] ^= base_ot->GetBlock(i, masked_choice[i]);
    send_msgs[i][1] ^= base_ot->GetBlock(i, 1 - masked_choice[i]);
  }

  ctx->SendAsync(
      ctx->NextRank(),
      ByteContainerView(send_msgs.data(), ot_num * 2 * sizeof(uint128_t)),
      "SGRR_OTE:SEND-CORR");
}

}  // namespace yacl::crypto
