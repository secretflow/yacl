// Copyright 2023 Ant Group Co., Ltd.
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

#include "yacl/kernel/algorithms/gywz_ote.h"

#include <cstdint>

#include "yacl/base/aligned_vector.h"
#include "yacl/base/byte_container_view.h"
#include "yacl/base/dynamic_bitset.h"
#include "yacl/base/exception.h"
#include "yacl/math/gadget.h"

namespace yacl::crypto {

namespace {
void CggmFullEval(uint128_t delta, uint128_t seed, uint32_t n,
                  absl::Span<uint128_t> all_msgs,
                  absl::Span<uint128_t> left_sums,
                  uint128_t one = Uint128Max()) {
  uint32_t height = math::Log2Ceil(n);
  YACL_ENFORCE(height == left_sums.size());
  YACL_ENFORCE(all_msgs.size() >= n);
  // if n is power of two,
  // all_msgs would have enough space to store the leaves
  bool is_two_power = (n == (static_cast<uint32_t>(1) << height));
  UninitAlignedVector<uint128_t> extra_buff;
  auto& working_seeds = all_msgs;

  // first level
  seed &= one;
  delta &= one;
  uint32_t prev_size = 1;
  working_seeds[0] = seed;
  working_seeds[1] = seed ^ delta;
  left_sums[0] = seed;

  for (uint32_t level = 1; level < height; ++level) {
    // the number of node in next level should be double
    prev_size <<= 1;
    uint128_t left_side_sum = 0;
    auto left_side = working_seeds.subspan(0, prev_size);
    auto right_side = working_seeds.subspan(prev_size, prev_size);
    if (!is_two_power && level == height - 1) {
      // all_msgs doesn't have enough space to store all leaves
      extra_buff.resize(prev_size);  // pre_size = 1 << (height - 1)
      right_side = absl::MakeSpan(extra_buff);
    }

    // copy previous seeds into right side
    memcpy(right_side.data(), left_side.data(), prev_size * sizeof(uint128_t));
    // perform Ccrhash(x)
    ParaCcrHashInplace_128(left_side);
    // G(x) = Ccrhash(x) || x ^ Ccrhash(x)
    for (uint32_t i = 0; i < prev_size; ++i) {
      left_side[i] &= one;
      right_side[i] ^= left_side[i];
      left_side_sum ^= left_side[i];
    }
    left_sums[level] = left_side_sum;
  }
  // copy right side leaves to all_msgs
  if (!is_two_power) {
    memcpy(all_msgs.data() + prev_size, extra_buff.data(),
           (n - prev_size) * sizeof(uint128_t));
  }
}

void CggmPuncFullEval(uint32_t index, absl::Span<const uint128_t> sibling_sums,
                      uint32_t n, absl::Span<uint128_t> punctured_msgs,
                      uint128_t one = Uint128Max()) {
  YACL_ENFORCE(punctured_msgs.size() >= n);
  uint32_t height = sibling_sums.size();
  UninitAlignedVector<uint128_t> extra_buff;

  // if n is power of two,
  // punctured_msgs would have enough space to store all leaves
  bool is_two_power = (n == (static_cast<uint32_t>(1) << (height)));
  auto& working_seeds = punctured_msgs;

  //  first level
  uint32_t prev_size = 1;
  uint32_t& mask = prev_size;
  working_seeds[0] = sibling_sums[0] & one;
  working_seeds[1] = sibling_sums[0] & one;
  uint32_t punctured_idx = index & 1;

  for (uint32_t level = 1; level < height; ++level) {
    // the number of seeds in next level
    prev_size <<= 1;
    uint128_t left_side_sum = sibling_sums[level];
    // uint128_t right_side_sum = sibling_sums[level];
    auto left_side = working_seeds.subspan(0, prev_size);
    auto right_side = working_seeds.subspan(prev_size, prev_size);
    if (!is_two_power && level == height - 1) {
      // punctured_msgs doesn't have enough space to store all leaves
      extra_buff.resize(prev_size);  // pre_size = 1 << (height - 1)
      right_side = absl::MakeSpan(extra_buff);
    }

    // copy previous seeds into right side
    memcpy(right_side.data(), left_side.data(), prev_size * sizeof(uint128_t));
    // perform Ccrhash(x)
    ParaCcrHashInplace_128(left_side);
    // G(x) = Ccrhash(x) || x ^ Ccrhash(x)
    for (uint32_t i = 0; i < prev_size; ++i) {
      left_side[i] &= one;
      left_side_sum ^= left_side[i];
      right_side[i] ^= left_side[i];
      // meaningless, right_side_sum == left_side_sum
      // right_side_sum ^= right_side[i];
    }
    left_side[punctured_idx] ^= left_side_sum;
    right_side[punctured_idx] ^= left_side_sum;
    // update punctured index
    punctured_idx |= index & mask;
  }
  // copy right side leaves to punctured_msgs
  if (!is_two_power) {
    memcpy(punctured_msgs.data() + prev_size, extra_buff.data(),
           (n - prev_size) * sizeof(uint128_t));
  }
}
}  // namespace

void GywzOtExtRecv(const std::shared_ptr<link::Context>& ctx,
                   const OtRecvStore& cot, uint32_t n, uint32_t index,
                   absl::Span<uint128_t> output) {
  const uint32_t height = math::Log2Ceil(n);
  YACL_ENFORCE(cot.Size() == height);
  YACL_ENFORCE_GT(n, (uint32_t)1);
  YACL_ENFORCE_GT(n, index);

  // Convert index into ot choices
  dynamic_bitset<uint128_t> choice;
  choice.append(index);
  choice.resize(height);
  dynamic_bitset<uint128_t> masked_choice = choice;
  for (uint32_t i = 0; i < height; ++i) {
    masked_choice[i] ^= cot.GetChoice(i);
  }

  YACL_ENFORCE(masked_choice.num_blocks() == 1);
  ctx->SendAsync(
      ctx->NextRank(),
      ByteContainerView(masked_choice.data(),
                        masked_choice.num_blocks() * sizeof(uint128_t)),
      "GYWZ_OTE: choice");

  // receive punctured seed thought cot
  auto recv_buf = ctx->Recv(ctx->NextRank(), "GYWZ_OTE: message");
  UninitAlignedVector<uint128_t> sibling_sums(height);
  memcpy(sibling_sums.data(), recv_buf.data(), recv_buf.size());
  for (uint32_t i = 0; i < height; ++i) {
    sibling_sums[i] ^= cot.GetBlock(i);
  }

  CggmPuncFullEval(index, absl::MakeConstSpan(sibling_sums), n, output);
}

void GywzOtExtSend(const std::shared_ptr<link::Context>& ctx,
                   const OtSendStore& cot, uint32_t n,
                   absl::Span<uint128_t> output) {
  const uint32_t height = math::Log2Ceil(n);
  YACL_ENFORCE(cot.Size() == height);
  YACL_ENFORCE_GT(n, (uint32_t)1);

  // get delta from cot
  uint128_t delta = cot.GetDelta();
  UninitAlignedVector<uint128_t> left_sums(height);
  uint128_t seed = SecureRandSeed();
  CggmFullEval(delta, seed, n, output, absl::MakeSpan(left_sums));

  dynamic_bitset<uint128_t> masked_choice(height);
  auto recv_buf = ctx->Recv(ctx->NextRank(), "GYWZ_OTE: choice");
  memcpy(masked_choice.data(), recv_buf.data(),
         masked_choice.num_blocks() * sizeof(uint128_t));

  for (uint32_t i = 0; i < height; ++i) {
    left_sums[i] ^= cot.GetBlock(i, 1 - masked_choice[i]);
  }
  ctx->SendAsync(
      ctx->NextRank(),
      ByteContainerView(left_sums.data(), sizeof(uint128_t) * height),
      "GYWZ_OTE: message");
}

void GywzOtExtRecv_ferret(const std::shared_ptr<link::Context>& ctx,
                          const OtRecvStore& cot, uint32_t n,
                          absl::Span<uint128_t> output) {
  uint32_t height = math::Log2Ceil(n);
  YACL_ENFORCE(cot.Size() == height);
  YACL_ENFORCE_GT(n, (uint32_t)1);
  YACL_ENFORCE(cot.Type() == OtStoreType::Compact);

  uint32_t index = 0;
  for (uint32_t i = 0; i < height; ++i) {
    index |= (cot.GetChoice(i)) << i;
  }
  uint128_t one = MakeUint128(0xffffffffffffffff, 0xfffffffffffffffe);

  auto recv_buf = ctx->Recv(ctx->NextRank(), "GYWZ_OTE: messages");
  UninitAlignedVector<uint128_t> sibling_sums(height);
  memcpy(sibling_sums.data(), recv_buf.data(), recv_buf.size());
  for (uint32_t i = 0; i < height; ++i) {
    sibling_sums[i] ^= (cot.GetBlock(i) & one);
  }

  CggmPuncFullEval(index, absl::MakeConstSpan(sibling_sums), n, output, one);

  // notice: "index" may be greater than n
  if (n > index) {
    output[index] |= ~one;
  }
}

void GywzOtExtSend_ferret(const std::shared_ptr<link::Context>& ctx,
                          const OtSendStore& cot, uint32_t n,
                          absl::Span<uint128_t> output) {
  uint32_t height = math::Log2Ceil(n);
  YACL_ENFORCE(cot.Size() == height);
  YACL_ENFORCE_GT(n, (uint32_t)1);
  YACL_ENFORCE(cot.Type() == OtStoreType::Compact);

  // get delta from cot
  uint128_t one = MakeUint128(0xffffffffffffffff, 0xfffffffffffffffe);

  uint128_t delta = cot.GetDelta() & one;
  uint128_t seed = SecureRandSeed() & one;

  UninitAlignedVector<uint128_t> left_sums(height);
  CggmFullEval(delta, seed, n, output, absl::MakeSpan(left_sums), one);

  for (uint32_t i = 0; i < height; ++i) {
    left_sums[i] ^= (cot.GetBlock(i, 1) & one);
  }
  ctx->SendAsync(
      ctx->NextRank(),
      ByteContainerView(left_sums.data(), sizeof(uint128_t) * height),
      "GYWZ_OTE: messages");
}

void GywzOtExtRecv_fixed_index(const std::shared_ptr<link::Context>& ctx,
                               const OtRecvStore& cot, uint32_t n,
                               absl::Span<uint128_t> output) {
  const uint32_t height = math::Log2Ceil(n);
  YACL_ENFORCE(cot.Size() == height);
  YACL_ENFORCE_GT(n, (uint32_t)1);

  auto recv_buf = ctx->Recv(ctx->NextRank(), "GYWZ_OTE: messages");
  YACL_ENFORCE(recv_buf.size() >=
               static_cast<int64_t>(height * sizeof(uint128_t)));
  auto recv_msgs =
      absl::MakeSpan(reinterpret_cast<uint128_t*>(recv_buf.data()), height);

  GywzOtExtRecv_fixed_index(cot, n, output, recv_msgs);
}

void GywzOtExtSend_fixed_index(const std::shared_ptr<link::Context>& ctx,
                               const OtSendStore& cot, uint32_t n,
                               absl::Span<uint128_t> output) {
  uint32_t height = math::Log2Ceil(n);
  YACL_ENFORCE(cot.Size() == height);
  YACL_ENFORCE_GT(n, (uint32_t)1);

  UninitAlignedVector<uint128_t> left_sums(height);
  GywzOtExtSend_fixed_index(cot, n, output, absl::MakeSpan(left_sums));

  ctx->SendAsync(
      ctx->NextRank(),
      ByteContainerView(left_sums.data(), sizeof(uint128_t) * height),
      "GYWZ_OTE: messages");
}

void GywzOtExtRecv_fixed_index(const OtRecvStore& cot, uint32_t n,
                               absl::Span<uint128_t> output,
                               absl::Span<uint128_t> recv_msgs) {
  const uint32_t height = math::Log2Ceil(n);
  YACL_ENFORCE(cot.Size() == height);
  YACL_ENFORCE_GT(n, (uint32_t)1);
  YACL_ENFORCE(recv_msgs.size() >= height);

  uint32_t index = 0;
  for (uint32_t i = 0; i < height; ++i) {
    index |= (cot.GetChoice(i)) << i;
  }

  UninitAlignedVector<uint128_t> sibling_sums(recv_msgs.data(),
                                              recv_msgs.data() + height);
  for (uint32_t i = 0; i < height; ++i) {
    sibling_sums[i] ^= cot.GetBlock(i);
  }
  CggmPuncFullEval(index, absl::MakeConstSpan(sibling_sums), n, output);
}

void GywzOtExtSend_fixed_index(const OtSendStore& cot, uint32_t n,
                               absl::Span<uint128_t> output,
                               absl::Span<uint128_t> send_msgs) {
  uint32_t height = math::Log2Ceil(n);
  YACL_ENFORCE(cot.Size() == height);
  YACL_ENFORCE_GT(n, (uint32_t)1);
  YACL_ENFORCE(send_msgs.size() >= height);

  uint128_t delta = cot.GetDelta();
  uint128_t seed = SecureRandSeed();
  CggmFullEval(delta, seed, n, output, send_msgs);
  for (uint32_t i = 0; i < height; ++i) {
    send_msgs[i] ^= cot.GetBlock(i, 1);
  }
}

}  // namespace yacl::crypto
