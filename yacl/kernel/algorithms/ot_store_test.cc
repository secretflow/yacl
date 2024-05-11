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

#include "yacl/kernel/algorithms/ot_store.h"

#include <future>
#include <memory>
#include <thread>
#include <tuple>
#include <utility>
#include <vector>

#include "fmt/format.h"
#include "gtest/gtest.h"

#include "yacl/base/exception.h"
#include "yacl/crypto/rand/rand.h"
#include "yacl/crypto/tools/prg.h"
#include "yacl/link/test_util.h"

namespace yacl::crypto {

namespace {

inline std::pair<OtRecvStore, std::vector<uint128_t>> RandOtRecvStore(
    uint64_t num) {
  auto recv_choices = RandBits<dynamic_bitset<uint128_t>>(num);
  auto recv_blocks = RandVec<uint128_t>(num);
  auto ot_store = MakeOtRecvStore(recv_choices, recv_blocks);
  return {ot_store, recv_blocks};
}

inline std::pair<OtRecvStore, std::vector<uint128_t>> RandCompactOtRecvStore(
    uint64_t num) {
  auto recv_blocks = RandVec<uint128_t>(num);
  auto ot_store = MakeCompactOtRecvStore(recv_blocks);
  return {ot_store, recv_blocks};
}

inline std::pair<OtSendStore, std::vector<std::array<uint128_t, 2>>>
RandOtSendStore(uint64_t /*num*/) {
  std::vector<std::array<uint128_t, 2>> blocks;
  Prg<uint128_t> prg;
  for (size_t i = 0; i < 25; i++) {
    std::array<uint128_t, 2> tmp;
    tmp[0] = prg();
    tmp[1] = prg();
    blocks.push_back(tmp);
  }
  auto ot_store = MakeOtSendStore(blocks);
  return {ot_store, blocks};
}

inline std::pair<OtSendStore, std::vector<std::array<uint128_t, 2>>>
RandCompactOtSendStore(uint64_t num) {
  auto inputs = RandVec<uint128_t>(num);
  auto delta = FastRandU128();
  std::vector<std::array<uint128_t, 2>> blocks;
  for (uint64_t i = 0; i < num; i++) {
    blocks.push_back({inputs[i], inputs[i] ^ delta});
  }
  auto ot_store = MakeCompactOtSendStore(inputs, delta);
  return {ot_store, blocks};
}
}  // namespace

TEST(OtRecvStoreTest, ConstructorTest) {
  // GIVEN
  const size_t ot_num = 100;
  auto recv_choices = RandBits<dynamic_bitset<uint128_t>>(ot_num);
  auto recv_blocks = RandVec<uint128_t>(ot_num);

  // WHEN
  auto ot_store = MakeOtRecvStore(recv_choices, recv_blocks);  // normal mode

  // THEN
  EXPECT_EQ(ot_store.Size(), ot_num);
  for (size_t i = 0; i < ot_num; ++i) {
    EXPECT_EQ(ot_store.GetBlock(i), recv_blocks[i]);
    EXPECT_EQ(ot_store.GetChoice(i), recv_choices[i]);
  }
}

TEST(OtRecvStoreTest, EmptyConstructorTest) {
  // GIVEN
  const size_t ot_num = 100;

  // WHEN
  auto ot_normal = OtRecvStore(ot_num, OtStoreType::Normal);
  auto ot_compact = OtRecvStore(ot_num, OtStoreType::Compact);

  // THEN
  EXPECT_EQ(ot_normal.Size(), ot_num);
  EXPECT_EQ(ot_compact.Size(), ot_num);

  for (size_t i = 0; i < ot_num; ++i) {
    EXPECT_EQ(ot_normal.GetBlock(i), 0);
    EXPECT_EQ(ot_compact.GetBlock(i), 0);
    EXPECT_EQ(ot_normal.GetChoice(i), 0);
    EXPECT_EQ(ot_compact.GetChoice(i), 0);
  }
}

TEST(OtRecvStoreTest, GetElementsTest) {
  // GIVEN
  const size_t ot_num = 100;
  auto recv_choices = RandBits<dynamic_bitset<uint128_t>>(ot_num);
  auto recv_blocks = RandVec<uint128_t>(ot_num);
  auto ot_store = MakeOtRecvStore(recv_choices, recv_blocks);

  // get element tests
  auto idx = RandInRange(ot_num);
  EXPECT_EQ(ot_store.GetChoice(idx), recv_choices[idx]);
  EXPECT_EQ(ot_store.GetBlock(idx), recv_blocks[idx]);

  EXPECT_EQ(ot_store.GetChoice(0), recv_choices[0]);
  EXPECT_EQ(ot_store.GetBlock(0), recv_blocks[0]);

  EXPECT_THROW(ot_store.GetChoice(ot_num + 1), yacl::Exception);
  EXPECT_THROW(ot_store.GetBlock(ot_num + 1), yacl::Exception);

  EXPECT_THROW(ot_store.GetChoice(-1), yacl::Exception);
  EXPECT_THROW(ot_store.GetBlock(-1), yacl::Exception);
}

TEST(OtSendStoreTest, ConstructorTest) {
  // GIVEN
  const uint64_t ot_num = 2;
  std::vector<std::array<uint128_t, 2>> blocks(ot_num);
  Prg<uint128_t> prg;
  for (size_t i = 0; i < ot_num; ++i) {
    blocks[i][0] = prg();
    blocks[i][1] = prg();
  }

  // WHEN
  auto ot_store = MakeOtSendStore(blocks);

  // THEN
  EXPECT_EQ(ot_store.Size(), ot_num);
  EXPECT_THROW(ot_store.GetDelta(), yacl::Exception);
  for (size_t i = 0; i < ot_num; ++i) {
    EXPECT_EQ(ot_store.GetBlock(i, 0), blocks[i][0]);
    EXPECT_EQ(ot_store.GetBlock(i, 1), blocks[i][1]);
  }
}

TEST(OtSendStoreTest, GetElementsTest) {
  // GIVEN
  std::vector<std::array<uint128_t, 2>> blocks;
  Prg<uint128_t> prg;
  for (size_t i = 0; i < 100; i++) {
    std::array<uint128_t, 2> tmp;
    tmp[0] = prg();
    tmp[1] = prg();
    blocks.push_back(tmp);
  }
  auto ot_store = MakeOtSendStore(blocks);

  // WHEN and THEN
  auto idx = RandInRange(100);
  EXPECT_EQ(ot_store.GetBlock(idx, 0), blocks[idx][0]);
}

#define OtSendStore_SLICE_TEST_INTERNAL(OT_STORE, BLOCKS)      \
  EXPECT_EQ((OT_STORE).Size(), 25);                            \
  /* get first slice (10) */                                   \
  {                                                            \
    /* only increase internal_use_ctr */                       \
    auto ot_sub = (OT_STORE).NextSlice(10);                    \
    auto idx = RandInRange(10);                                \
    EXPECT_EQ(ot_sub.Size(), 10);                              \
    EXPECT_EQ(ot_sub.GetBlock(idx, 0), (BLOCKS)[idx][0]);      \
  }                                                            \
                                                               \
  /* get first slice (12) */                                   \
  {                                                            \
    /* only increase internal_use_ctr */                       \
    auto ot_sub = (OT_STORE).NextSlice(12);                    \
    auto idx = RandInRange(12);                                \
    EXPECT_EQ(ot_sub.Size(), 12);                              \
    EXPECT_EQ(ot_sub.GetBlock(idx, 0), (BLOCKS)[idx + 10][0]); \
  }                                                            \
                                                               \
  /* get first slice (15) */                                   \
  {                                                            \
    EXPECT_THROW((OT_STORE).NextSlice(15), yacl::Exception);   \
                                                               \
    /* only increase internal_use_ctr */                       \
    auto ot_sub = (OT_STORE).NextSlice(3);                     \
    auto idx = RandInRange(3);                                 \
    EXPECT_EQ(ot_sub.Size(), 3);                               \
    EXPECT_EQ(ot_sub.GetBlock(idx, 0), (BLOCKS)[idx + 22][0]); \
  }

#define OtRecvStore_SLICE_TEST_INTERNAL(OT_STORE, BLOCKS)    \
  EXPECT_EQ((OT_STORE).Size(), 25);                          \
  /* get first slice (10) */                                 \
  {                                                          \
    /* only increase internal_use_ctr */                     \
    auto ot_sub = (OT_STORE).NextSlice(10);                  \
    auto idx = RandInRange(10);                              \
    EXPECT_EQ(ot_sub.Size(), 10);                            \
    EXPECT_EQ(ot_sub.GetBlock(idx), (BLOCKS)[idx]);          \
  }                                                          \
                                                             \
  /* get first slice (12) */                                 \
  {                                                          \
    /* only increase internal_use_ctr */                     \
    auto ot_sub = (OT_STORE).NextSlice(12);                  \
    auto idx = RandInRange(12);                              \
    EXPECT_EQ(ot_sub.Size(), 12);                            \
    EXPECT_EQ(ot_sub.GetBlock(idx), (BLOCKS)[idx + 10]);     \
  }                                                          \
                                                             \
  /* get first slice (15) */                                 \
  {                                                          \
    EXPECT_THROW((OT_STORE).NextSlice(15), yacl::Exception); \
                                                             \
    /* only increase internal_use_ctr */                     \
    auto ot_sub = (OT_STORE).NextSlice(3);                   \
    auto idx = RandInRange(3);                               \
    EXPECT_EQ(ot_sub.Size(), 3);                             \
    EXPECT_EQ(ot_sub.GetBlock(idx), (BLOCKS)[idx + 22]);     \
  }

#define SLICE_TEST(TYPE)                             \
  /* Normal Slice Test */                            \
  TEST(TYPE##Test, TYPE##SliceNormalTest) {          \
    auto [ot_store, blocks] = Rand##TYPE(25);        \
    TYPE##_SLICE_TEST_INTERNAL(ot_store, blocks);    \
  }                                                  \
  /* Compact Slice Test */                           \
  TEST(TYPE##Test, TYPE##SliceCompactTest) {         \
    auto [ot_store, blocks] = RandCompact##TYPE(25); \
    TYPE##_SLICE_TEST_INTERNAL(ot_store, blocks);    \
  }  // namespace yacl::crypto

SLICE_TEST(OtSendStore)
SLICE_TEST(OtRecvStore)

TEST(MockRotTest, Works) {
  // GIVEN
  const size_t ot_num = 100;

  // WHEN
  auto rot = MockRots(ot_num);

  // THEN
  EXPECT_EQ(rot.send.Size(), ot_num);
  EXPECT_EQ(rot.recv.Size(), ot_num);
  for (size_t i = 0; i < ot_num; ++i) {
    auto choice = rot.recv.GetChoice(i);
    EXPECT_EQ(rot.send.GetBlock(i, choice), rot.recv.GetBlock(i));
  }
}

TEST(MockCotTest, Works) {
  // GIVEN
  const size_t ot_num = 2;
  auto delta = FastRandU128();

  // WHEN
  auto cot = MockCots(ot_num, delta);

  // THEN
  EXPECT_EQ(cot.send.Size(), ot_num);
  EXPECT_EQ(cot.recv.Size(), ot_num);
  EXPECT_EQ(cot.send.GetDelta(), delta);
  for (size_t i = 0; i < ot_num; ++i) {
    auto choice = cot.recv.GetChoice(i);
    EXPECT_EQ(cot.send.GetBlock(i, choice), cot.recv.GetBlock(i));
    EXPECT_EQ(delta, cot.send.GetBlock(i, 0) ^ cot.send.GetBlock(i, 1));
  }
}

TEST(MockCompactCotTest, Works) {
  // GIVEN
  const size_t ot_num = 100;

  // WHEN
  auto cot = MockCompactOts(ot_num);

  // THEN
  EXPECT_EQ(cot.send.GetDelta() & 0x1, 1);
  for (size_t i = 0; i < ot_num; ++i) {
    auto choice = cot.recv.GetChoice(i);
    EXPECT_EQ(cot.send.GetBlock(i, choice), cot.recv.GetBlock(i));
  }
}

}  // namespace yacl::crypto
