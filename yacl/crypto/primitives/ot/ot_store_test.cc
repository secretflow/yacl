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

#include "yacl/crypto/primitives/ot/ot_store.h"

#include <future>
#include <memory>
#include <thread>
#include <utility>
#include <vector>

#include "fmt/format.h"
#include "gtest/gtest.h"

#include "yacl/base/exception.h"
#include "yacl/crypto/utils/rand.h"
#include "yacl/link/test_util.h"

namespace yacl::crypto {

TEST(OtRecvStoreTest, ConstructorTest) {
  // GIVEN
  const size_t ot_num = 100;
  auto recv_choices = RandBits<dynamic_bitset<uint128_t>>(ot_num);
  auto recv_blocks = RandVec<uint128_t>(ot_num);

  // WHEN
  auto ot_store = MakeOtRecvStore(recv_choices, recv_blocks);  // normal mode

  // THEN
  EXPECT_EQ(ot_store->Size(), ot_num);
  for (size_t i = 0; i < ot_num; ++i) {
    EXPECT_EQ(ot_store->GetBlock(i), recv_blocks[i]);
    EXPECT_EQ(ot_store->GetChoice(i), recv_choices[i]);
  }
}

TEST(OtRecvStoreTest, EmptyConstructorTest) {
  // GIVEN
  const size_t ot_num = 100;

  // WHEN
  auto ot_normal = std::make_shared<OtRecvStore>(ot_num, false);
  auto ot_compact = std::make_shared<OtRecvStore>(ot_num, true);

  // THEN
  EXPECT_EQ(ot_normal->Size(), ot_num);
  EXPECT_EQ(ot_compact->Size(), ot_num);

  for (size_t i = 0; i < ot_num; ++i) {
    EXPECT_EQ(ot_normal->GetBlock(i), 0);
    EXPECT_EQ(ot_compact->GetBlock(i), 0);
    EXPECT_EQ(ot_normal->GetChoice(i), 0);
    EXPECT_EQ(ot_compact->GetChoice(i), 0);
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
  EXPECT_EQ(ot_store->GetChoice(idx), recv_choices[idx]);
  EXPECT_EQ(ot_store->GetBlock(idx), recv_blocks[idx]);

  EXPECT_EQ(ot_store->GetChoice(0), recv_choices[0]);
  EXPECT_EQ(ot_store->GetBlock(0), recv_blocks[0]);

  EXPECT_THROW(ot_store->GetChoice(ot_num + 1), yacl::Exception);
  EXPECT_THROW(ot_store->GetBlock(ot_num + 1), yacl::Exception);

  EXPECT_THROW(ot_store->GetChoice(-1), yacl::Exception);
  EXPECT_THROW(ot_store->GetBlock(-1), yacl::Exception);
}

TEST(OtRecvStoreTest, SliceTest) {
  // ot recv msgs and blocks
  auto recv_choices = RandBits<dynamic_bitset<uint128_t>>(25);
  auto recv_blocks = RandVec<uint128_t>(25);
  auto ot_store = MakeOtRecvStore(recv_choices, recv_blocks);
  EXPECT_EQ(ot_store->Size(), 25);

  // get first slice (10)
  {
    auto ot_sub = ot_store->NextSlice(10);
    EXPECT_EQ(ot_sub->Size(), 10);

    auto idx = RandInRange(10);
    EXPECT_EQ(ot_sub->GetChoice(idx), ot_store->GetChoice(idx));
    EXPECT_EQ(ot_sub->GetBlock(idx), ot_store->GetBlock(idx));

    EXPECT_EQ(ot_sub->GetChoice(0), ot_store->GetChoice(0));
    EXPECT_EQ(ot_sub->GetBlock(0), ot_store->GetBlock(0));

    EXPECT_THROW(ot_sub->GetChoice(11), yacl::Exception);
    EXPECT_THROW(ot_sub->GetBlock(11), yacl::Exception);

    EXPECT_THROW(ot_sub->GetChoice(-1), yacl::Exception);
    EXPECT_THROW(ot_sub->GetBlock(-1), yacl::Exception);
  }

  // get second slice (12)
  {
    auto ot_sub = ot_store->NextSlice(12);
    EXPECT_EQ(ot_sub->Size(), 12);

    auto idx = RandInRange(12);
    EXPECT_EQ(ot_sub->GetChoice(idx), ot_store->GetChoice(idx + 10));
    EXPECT_EQ(ot_sub->GetBlock(idx), ot_store->GetBlock(idx + 10));

    EXPECT_EQ(ot_sub->GetChoice(0), ot_store->GetChoice(10));
    EXPECT_EQ(ot_sub->GetBlock(0), ot_store->GetBlock(10));

    EXPECT_THROW(ot_sub->GetChoice(13), yacl::Exception);
    EXPECT_THROW(ot_sub->GetBlock(13), yacl::Exception);

    EXPECT_THROW(ot_sub->GetChoice(-1), yacl::Exception);
    EXPECT_THROW(ot_sub->GetBlock(-1), yacl::Exception);
  }

  // get third slice (3)
  {
    EXPECT_THROW(ot_store->NextSlice(15), yacl::Exception);  // should failed

    auto ot_sub = ot_store->NextSlice(3);
    EXPECT_EQ(ot_sub->Size(), 3);

    auto idx = RandInRange(3);
    EXPECT_EQ(ot_sub->GetChoice(idx), recv_choices[idx + 22]);
    EXPECT_EQ(ot_sub->GetBlock(idx), recv_blocks[idx + 22]);

    EXPECT_EQ(ot_sub->GetChoice(0), ot_store->GetChoice(22));
    EXPECT_EQ(ot_sub->GetBlock(0), ot_store->GetBlock(22));

    EXPECT_THROW(ot_sub->GetChoice(4), yacl::Exception);
    EXPECT_THROW(ot_sub->GetBlock(4), yacl::Exception);

    EXPECT_THROW(ot_sub->GetChoice(-1), yacl::Exception);
    EXPECT_THROW(ot_sub->GetBlock(-1), yacl::Exception);
  }
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
  EXPECT_EQ(ot_store->Size(), ot_num);
  EXPECT_THROW(ot_store->GetDelta(), yacl::Exception);
  for (size_t i = 0; i < ot_num; ++i) {
    EXPECT_EQ(ot_store->GetBlock(i, 0), blocks[i][0]);
    EXPECT_EQ(ot_store->GetBlock(i, 1), blocks[i][1]);
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
  EXPECT_EQ(ot_store->GetBlock(idx, 0), blocks[idx][0]);
}

TEST(OtSendStoreTest, SliceTest) {
  // ot send msgs and blocks
  std::vector<std::array<uint128_t, 2>> blocks;
  Prg<uint128_t> prg;
  for (size_t i = 0; i < 25; i++) {
    std::array<uint128_t, 2> tmp;
    tmp[0] = prg();
    tmp[1] = prg();
    blocks.push_back(tmp);
  }
  auto ot_store = MakeOtSendStore(blocks);
  EXPECT_EQ(ot_store->Size(), 25);

  // get first slice (10)
  {
    auto ot_sub = ot_store->NextSlice(10);  // only increase internal_use_ctr
    auto idx = RandInRange(10);
    EXPECT_EQ(ot_sub->Size(), 10);
    EXPECT_EQ(ot_sub->GetBlock(idx, 0), blocks[idx][0]);
  }

  // get second slice (12)
  {
    auto ot_sub = ot_store->NextSlice(12);  // only increase internal_use_ctr
    auto idx = RandInRange(12);
    EXPECT_EQ(ot_sub->Size(), 12);
    EXPECT_EQ(ot_sub->GetBlock(idx, 0), blocks[idx + 10][0]);
  }

  // get second slice (15)
  {
    EXPECT_THROW(ot_store->NextSlice(15), yacl::Exception);

    auto ot_sub = ot_store->NextSlice(3);  // only increase internal_use_ctr
    auto idx = RandInRange(3);
    EXPECT_EQ(ot_sub->Size(), 3);
    EXPECT_EQ(ot_sub->GetBlock(idx, 0), blocks[idx + 22][0]);
  }
}

TEST(MockRotTest, Works) {
  // GIVEN
  const size_t ot_num = 100;

  // WHEN
  auto rot = MockRots(ot_num);

  // THEN
  EXPECT_EQ(rot.send->Size(), ot_num);
  EXPECT_EQ(rot.recv->Size(), ot_num);
  for (size_t i = 0; i < ot_num; ++i) {
    auto choice = rot.recv->GetChoice(i);
    EXPECT_EQ(rot.send->GetBlock(i, choice), rot.recv->GetBlock(i));
  }
}

TEST(MockCotTest, Works) {
  // GIVEN
  const size_t ot_num = 2;
  auto delta = RandU128();

  // WHEN
  auto cot = MockCots(ot_num, delta);

  // THEN
  EXPECT_EQ(cot.send->Size(), ot_num);
  EXPECT_EQ(cot.recv->Size(), ot_num);
  EXPECT_EQ(cot.send->GetDelta(), delta);
  for (size_t i = 0; i < ot_num; ++i) {
    auto choice = cot.recv->GetChoice(i);
    EXPECT_EQ(cot.send->GetBlock(i, choice), cot.recv->GetBlock(i));
    EXPECT_EQ(delta, cot.send->GetBlock(i, 0) ^ cot.send->GetBlock(i, 1));
  }
}

TEST(MockCompactCotTest, Works) {
  // GIVEN
  const size_t ot_num = 100;

  // WHEN
  auto cot = MockCompactCots(ot_num);

  // THEN
  EXPECT_EQ(cot.send->GetDelta() & 0x1, 1);
  for (size_t i = 0; i < ot_num; ++i) {
    auto choice = cot.recv->GetChoice(i);
    EXPECT_EQ(cot.send->GetBlock(i, choice), cot.recv->GetBlock(i));
  }
}

}  // namespace yacl::crypto
