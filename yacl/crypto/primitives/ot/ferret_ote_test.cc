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

#include "yacl/crypto/primitives/ot/ferret_ote.h"

#include <algorithm>
#include <future>
#include <memory>
#include <thread>

#include "gtest/gtest.h"

#include "yacl/base/dynamic_bitset.h"
#include "yacl/base/exception.h"
#include "yacl/base/int128.h"
#include "yacl/crypto/primitives/ot/ot_store.h"
#include "yacl/crypto/tools/prg.h"
#include "yacl/crypto/utils/rand.h"
#include "yacl/link/test_util.h"

namespace yacl::crypto {

struct SpParams {
  size_t range_n;  // range
};

struct MpParams {
  size_t idx_num;    // poit num
  size_t idx_range;  // range
};

struct FerretParams {
  size_t ot_num;  // output ot num
};

class SpOtExtTest : public ::testing::TestWithParam<SpParams> {};
class MpOtExtTest : public ::testing::TestWithParam<MpParams> {};
class FerretOtExtTest : public ::testing::TestWithParam<FerretParams> {};

TEST_P(SpOtExtTest, Works) {
  // GIVEN
  const int kWorldSize = 2;
  const size_t range_n = GetParam().range_n;

  auto lctxs = link::test::SetupWorld(kWorldSize);  // setup network
  uint128_t delta = RandU128();                     // cot delta
  auto option = MakeSpCotOption(range_n);           // make option
  auto cots = MockCots(option.cot_num, delta);      // mock cot
  size_t index = RandInRange(range_n);              // get input

  // WHEN
  std::vector<uint128_t> send_out(range_n);
  std::vector<uint128_t> recv_out(range_n);
  std::future<void> sender = std::async([&] {
    SpCotSend(lctxs[0], cots.send, option, absl::MakeSpan(send_out));
  });
  std::future<void> receiver = std::async([&] {
    SpCotRecv(lctxs[1], cots.recv, option, index, absl::MakeSpan(recv_out));
  });
  receiver.get();
  sender.get();

  // THEN
  for (size_t i = 0; i < range_n; ++i) {
    if (index != i) {                       // if i is not the chosen index,
      EXPECT_EQ(send_out[i], recv_out[i]);  // result is same
    } else {                                // if i is  the chosen index,
      EXPECT_EQ(delta, recv_out[i] ^ send_out[i]);  // xor results = delta
    }
  }
}

TEST_P(MpOtExtTest, NoCuckooWorks) {
  // GIVEN
  const int kWorldSize = 2;
  const size_t idx_num = GetParam().idx_num;
  const size_t idx_range = GetParam().idx_range;

  auto lctxs = link::test::SetupWorld(kWorldSize);  // setup network
  uint128_t delta = RandU128();                     // cot delta
  auto idxes =
      MakeRegularRandChoices(idx_num, idx_range);  // make random choices
  auto option = MakeMpCotOption(idx_num, idx_range, false);  // make option
  auto cots = MockCots(option.cot_num, delta);               // mock cot

  // WHEN
  std::vector<uint128_t> send_out(idx_range);
  std::vector<uint128_t> recv_out(idx_range);
  std::future<void> sender = std::async([&] {
    MpCotSend(lctxs[0], cots.send, option, absl::MakeSpan(send_out));
  });
  std::future<void> receiver = std::async([&] {
    MpCotRecv(lctxs[1], cots.recv, option, idxes, absl::MakeSpan(recv_out));
  });
  receiver.get();
  sender.get();

  // THEN
  for (size_t i = 0; i < idx_range; ++i) {
    if (std::count(idxes.begin(), idxes.end(), i) != 0) {
      EXPECT_NE(send_out[i], recv_out[i]);  // the punctured points
      EXPECT_EQ(delta, send_out[i] ^ recv_out[i]);
    } else {
      EXPECT_EQ(send_out[i], recv_out[i]);
    }
  }
}

TEST_P(MpOtExtTest, CuckooWorks) {
  // GIVEN
  const int kWorldSize = 2;
  const size_t idx_num = GetParam().idx_num;
  const size_t idx_range = GetParam().idx_range;

  auto lctxs = link::test::SetupWorld(kWorldSize);          // setup network
  uint128_t delta = RandU128();                             // cot delta
  auto option = MakeMpCotOption(idx_num, idx_range, true);  // make option
  auto cots = MockCots(option.cot_num, delta);              // mock cot

  std::vector<uint64_t> idxes(idx_range);
  std::iota(std::begin(idxes), std::end(idxes), 0);
  std::shuffle(idxes.begin(), idxes.end(), std::default_random_engine(0));
  idxes.resize(idx_num);

  // WHEN
  std::vector<uint128_t> send_out(idx_range);
  std::vector<uint128_t> recv_out(idx_range);
  std::future<void> sender = std::async([&] {
    MpCotSend(lctxs[0], cots.send, option, absl::MakeSpan(send_out));
  });
  std::future<void> receiver = std::async([&] {
    MpCotRecv(lctxs[1], cots.recv, option, idxes, absl::MakeSpan(recv_out));
  });
  receiver.get();
  sender.get();

  // THEN
  for (size_t i = 0; i < idx_range; ++i) {
    if (std::count(idxes.begin(), idxes.end(), i) != 0) {
      EXPECT_NE(send_out[i], recv_out[i]);  // the punctured points
      EXPECT_EQ(delta, send_out[i] ^ recv_out[i]);
    } else {
      EXPECT_EQ(send_out[i], recv_out[i]);
    }
  }
}

TEST_P(FerretOtExtTest, Works) {
  // GIVEN
  const int kWorldSize = 2;
  const size_t ot_num = GetParam().ot_num;

  auto lctxs = link::test::SetupWorld(kWorldSize);  // setup network
  // uint128_t delta = RandU128();                     // cot delta
  auto option =
      MakeFerretOtExtOption(LpnParam::GetDefault(), ot_num);  // make option
  auto cots_compact = MockCompactOts(option.cot_num);         // mock cots

  // WHEN
  auto sender = std::async([&] {
    return FerretOtExtSend(lctxs[0], cots_compact.send, option, ot_num);
  });
  auto receiver = std::async([&] {
    return FerretOtExtRecv(lctxs[1], cots_compact.recv, option, ot_num);
  });
  auto ot_recv = receiver.get();
  auto ot_send = sender.get();

  // THEN
  auto zero = MakeUint128(0, 0);
  auto delta = ot_send->GetDelta();
  for (size_t i = 0; i < ot_num; ++i) {
    EXPECT_EQ(ot_send->GetBlock(i, ot_recv->GetChoice(i)),
              ot_recv->GetBlock(i));  // rot correlation
    EXPECT_EQ(ot_send->GetBlock(i, 0) ^ ot_send->GetBlock(i, 1),
              delta);  // cot correlation
    EXPECT_NE(ot_send->GetBlock(i, ot_recv->GetChoice(i)), zero);
  }
}

INSTANTIATE_TEST_SUITE_P(Works_Instances, SpOtExtTest,
                         testing::Values(SpParams{16},  //
                                         SpParams{3},
                                         SpParams{8192}));  // lpn batch

INSTANTIATE_TEST_SUITE_P(Works_Instances, MpOtExtTest,
                         testing::Values(MpParams{2, 16},
                                         MpParams{57, 1024}));  // lpn batch

INSTANTIATE_TEST_SUITE_P(Works_Instances, FerretOtExtTest,
                         testing::Values(FerretParams{1 << 20},  // 1 batch
                                         FerretParams{1 << 21}));

}  // namespace yacl::crypto
