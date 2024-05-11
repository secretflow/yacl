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

#include "yacl/kernel/algorithms/ferret_ote.h"

#include <algorithm>
#include <future>
#include <memory>
#include <thread>

#include "gtest/gtest.h"

#include "yacl/base/aligned_vector.h"
#include "yacl/base/dynamic_bitset.h"
#include "yacl/base/exception.h"
#include "yacl/base/int128.h"
#include "yacl/crypto/rand/rand.h"
#include "yacl/crypto/tools/prg.h"
#include "yacl/kernel/algorithms/ot_store.h"
#include "yacl/link/test_util.h"

namespace yacl::crypto {

struct FerretParams {
  size_t ot_num;           // output ot num
  LpnNoiseAsm assumption;  // noise assumption
};

class FerretOtExtTest : public ::testing::TestWithParam<FerretParams> {};

TEST_P(FerretOtExtTest, Works) {
  // GIVEN
  const int kWorldSize = 2;
  const size_t ot_num = GetParam().ot_num;
  const auto assumption = GetParam().assumption;

  auto lctxs = link::test::SetupWorld(kWorldSize);  // setup network
  auto lpn_param = LpnParam(10485760, 452000, 1280, assumption);
  auto cot_num = FerretCotHelper(lpn_param, ot_num);  // make option
  auto cots_compact = MockCompactOts(cot_num);        // mock cots

  // WHEN
  auto sender = std::async([&] {
    return FerretOtExtSend(lctxs[0], cots_compact.send, lpn_param, ot_num);
  });
  auto receiver = std::async([&] {
    return FerretOtExtRecv(lctxs[1], cots_compact.recv, lpn_param, ot_num);
  });
  auto ot_recv = receiver.get();
  auto ot_send = sender.get();

  // THEN
  auto zero = MakeUint128(0, 0);
  auto delta = ot_send.GetDelta();
  for (size_t i = 0; i < ot_num; ++i) {
    EXPECT_EQ(ot_send.GetBlock(i, ot_recv.GetChoice(i)),
              ot_recv.GetBlock(i));  // correctness
    EXPECT_EQ(ot_send.GetBlock(i, 0) ^ ot_send.GetBlock(i, 1),
              delta);  // correctness
    EXPECT_NE(ot_send.GetBlock(i, ot_recv.GetChoice(i)),
              zero);  // ot block can not be zero
    EXPECT_NE(ot_send.GetBlock(i, 1 - ot_recv.GetChoice(i)),
              zero);  // ot block can not be zero
  }
}

TEST_P(FerretOtExtTest, CheetahWorks) {
  // GIVEN
  const int kWorldSize = 2;
  const size_t ot_num = GetParam().ot_num;
  const auto assumption = GetParam().assumption;

  auto lctxs = link::test::SetupWorld(kWorldSize);  // setup network
  auto lpn_param = LpnParam(10485760, 452000, 1280, assumption);
  auto cot_num = FerretCotHelper(lpn_param, ot_num);  // make option
  auto cots_compact = MockCompactOts(cot_num);        // mock cots
  auto delta = cots_compact.send.GetDelta();

  auto send_out = UninitAlignedVector<uint128_t>(ot_num);
  auto recv_out = UninitAlignedVector<uint128_t>(ot_num);
  // WHEN
  auto sender = std::async([&] {
    FerretOtExtSend_cheetah(lctxs[0], cots_compact.send, lpn_param, ot_num,
                            absl::MakeSpan(send_out));
  });
  auto receiver = std::async([&] {
    FerretOtExtRecv_cheetah(lctxs[1], cots_compact.recv, lpn_param, ot_num,
                            absl::MakeSpan(recv_out));
  });
  receiver.get();
  sender.get();

  auto ot_recv = MakeCompactOtRecvStore(std::move(recv_out));
  auto ot_send = MakeCompactOtSendStore(std::move(send_out), delta);

  // THEN
  auto zero = MakeUint128(0, 0);
  for (size_t i = 0; i < ot_num; ++i) {
    EXPECT_EQ(ot_send.GetBlock(i, ot_recv.GetChoice(i)),
              ot_recv.GetBlock(i));  // correctness
    EXPECT_EQ(ot_send.GetBlock(i, 0) ^ ot_send.GetBlock(i, 1),
              delta);  // correctness
    EXPECT_NE(ot_send.GetBlock(i, ot_recv.GetChoice(i)),
              zero);  // ot block can not be zero
    EXPECT_NE(ot_send.GetBlock(i, 1 - ot_recv.GetChoice(i)),
              zero);  // ot block can not be zero
  }
}

INSTANTIATE_TEST_SUITE_P(
    Works_Instances, FerretOtExtTest,
    testing::Values(FerretParams{81921, LpnNoiseAsm::RegularNoise},
                    FerretParams{10485760, LpnNoiseAsm::RegularNoise},
                    FerretParams{10485761, LpnNoiseAsm::RegularNoise},
                    FerretParams{1 << 20, LpnNoiseAsm::RegularNoise}
                    // FerretParams{1 << 21, LpnNoiseAsm::RegularNoise},
                    // FerretParams{1 << 22, LpnNoiseAsm::RegularNoise},
                    // FerretParams{1 << 23, LpnNoiseAsm::RegularNoise},
                    // FerretParams{1 << 24, LpnNoiseAsm::RegularNoise},
                    // FerretParams{1 << 25, LpnNoiseAsm::RegularNoise}
                    ));

TEST(FerretOtExtEdgeTest, Test1) {
  // GIVEN
  const int kWorldSize = 2;
  const auto assumption = LpnNoiseAsm::RegularNoise;

  auto lctxs = link::test::SetupWorld(kWorldSize);  // setup network
  auto lpn_param = LpnParam(10485760, 452000, 1280, assumption);

  // ot_num < minium size of base_cot
  const size_t ot_num = 2 * lpn_param.t - 1;
  auto cot_num = FerretCotHelper(lpn_param, ot_num);  // make option
  auto cots_compact = MockCompactOts(cot_num);        // mock cots

  // WHEN
  auto sender = std::async([&] {
    ASSERT_THROW(
        FerretOtExtSend(lctxs[0], cots_compact.send, lpn_param, ot_num),
        ::yacl::Exception);
  });
  auto receiver = std::async([&] {
    ASSERT_THROW(
        FerretOtExtRecv(lctxs[1], cots_compact.recv, lpn_param, ot_num),
        ::yacl::Exception);
  });
  sender.get();
  receiver.get();
}

TEST(FerretOtExtEdgeTest, Test2) {
  // Given
  const int kWorldSize = 2;
  const auto assumption = LpnNoiseAsm::RegularNoise;

  auto lctxs = link::test::SetupWorld(kWorldSize);  // setup network
  auto lpn_param = LpnParam(10485760, 452000, 1280, assumption);
  auto ot_num = 2 * lpn_param.t;
  auto cot_num = FerretCotHelper(lpn_param, ot_num);  // make option
  auto cots_compact = MockCompactOts(cot_num);        // mock cots

  // WHEN
  auto sender = std::async([&] {
    return FerretOtExtSend(lctxs[0], cots_compact.send, lpn_param, ot_num);
  });
  auto receiver = std::async([&] {
    return FerretOtExtRecv(lctxs[1], cots_compact.recv, lpn_param, ot_num);
  });
  auto ot_recv = receiver.get();
  auto ot_send = sender.get();

  // THEN
  auto zero = MakeUint128(0, 0);
  auto delta = ot_send.GetDelta();
  for (size_t i = 0; i < ot_num; ++i) {
    EXPECT_EQ(ot_send.GetBlock(i, ot_recv.GetChoice(i)),
              ot_recv.GetBlock(i));  // correctness
    EXPECT_EQ(ot_send.GetBlock(i, 0) ^ ot_send.GetBlock(i, 1),
              delta);  // correctness
    EXPECT_NE(ot_send.GetBlock(i, ot_recv.GetChoice(i)),
              zero);  // ot block can not be zero
    EXPECT_NE(ot_send.GetBlock(i, 1 - ot_recv.GetChoice(i)),
              zero);  // ot block can not be zero
  }
}
}  // namespace yacl::crypto
