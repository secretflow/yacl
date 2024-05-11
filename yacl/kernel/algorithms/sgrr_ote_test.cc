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

#include "yacl/kernel/algorithms/sgrr_ote.h"

#include <future>
#include <thread>
#include <utility>
#include <vector>

#include "fmt/format.h"
#include "gtest/gtest.h"

#include "yacl/base/exception.h"
#include "yacl/kernel/algorithms/ot_store.h"
#include "yacl/link/test_util.h"
#include "yacl/math/gadget.h"

namespace yacl::crypto {

struct TestParams {
  unsigned n;
};

class SgrrParamTest : public ::testing::TestWithParam<TestParams> {};

TEST_P(SgrrParamTest, SemiHonestWorks) {
  size_t n = GetParam().n;

  auto index = RandInRange(n);
  auto lctxs = link::test::SetupWorld(2);
  auto base_ot = MockRots(math::Log2Ceil(n));  // mock many base OTs

  std::vector<uint128_t> send_out(n);
  std::vector<uint128_t> recv_out(n);

  std::future<void> receiver = std::async([&] {
    SgrrOtExtRecv(lctxs[0], std::move(base_ot.recv), n, index,
                  absl::MakeSpan(recv_out), false);
  });
  std::future<void> sender = std::async([&] {
    SgrrOtExtSend(lctxs[1], std::move(base_ot.send), n,
                  absl::MakeSpan(send_out), false);
  });
  sender.get();
  receiver.get();

  EXPECT_EQ(send_out.size(), n);
  EXPECT_EQ(recv_out.size(), n);

  for (size_t i = 0; i < n; ++i) {
    if (index != i) {
      EXPECT_NE(recv_out[i], 0);
      EXPECT_EQ(send_out[i], recv_out[i]);
    } else {
      EXPECT_EQ(0, recv_out[i]);
    }
  }
}

TEST_P(SgrrParamTest, MaliciousWorks) {
  size_t n = GetParam().n;

  auto index = RandInRange(n);
  auto lctxs = link::test::SetupWorld(2);
  auto base_ot = MockRots(math::Log2Ceil(n));  // mock many base OTs

  std::vector<uint128_t> send_out(n);
  std::vector<uint128_t> recv_out(n);

  std::future<void> receiver = std::async([&] {
    SgrrOtExtRecv(lctxs[0], std::move(base_ot.recv), n, index,
                  absl::MakeSpan(recv_out), true);
  });
  std::future<void> sender = std::async([&] {
    SgrrOtExtSend(lctxs[1], std::move(base_ot.send), n,
                  absl::MakeSpan(send_out), true);
  });
  sender.get();
  receiver.get();

  EXPECT_EQ(send_out.size(), n);
  EXPECT_EQ(recv_out.size(), n);

  for (size_t i = 0; i < n; ++i) {
    if (index != i) {
      EXPECT_NE(recv_out[i], 0);
      EXPECT_EQ(send_out[i], recv_out[i]);
    } else {
      EXPECT_EQ(0, recv_out[i]);
    }
  }
}

TEST_P(SgrrParamTest, SemiHonestFixedIndextWorks) {
  size_t n = GetParam().n;

  auto lctxs = link::test::SetupWorld(2);
  auto ot_num = math::Log2Ceil(n);
  auto index = RandInRange(n);
  dynamic_bitset<uint128_t> choices;
  choices.append(index);
  choices.resize(ot_num);
  auto base_ot = MockRots(ot_num, choices);  // mock many base OTs

  std::vector<uint128_t> send_out(n);
  std::vector<uint128_t> recv_out(n);

  std::future<void> receiver = std::async([&] {
    SgrrOtExtRecv_fixed_index(lctxs[0], std::move(base_ot.recv), n,
                              absl::MakeSpan(recv_out));
  });
  std::future<void> sender = std::async([&] {
    SgrrOtExtSend_fixed_index(lctxs[1], std::move(base_ot.send), n,
                              absl::MakeSpan(send_out));
  });
  sender.get();
  receiver.get();

  for (size_t i = 0; i < n; ++i) {
    if (index != i) {
      EXPECT_NE(recv_out[i], 0);
      EXPECT_EQ(send_out[i], recv_out[i]);
    } else {
      EXPECT_EQ(0, recv_out[i]);
    }
  }
}

TEST_P(SgrrParamTest, MaliciousFixedIndextWorks) {
  size_t n = GetParam().n;

  auto lctxs = link::test::SetupWorld(2);
  auto ot_num = math::Log2Ceil(n);
  auto index = RandInRange(n);
  dynamic_bitset<uint128_t> choices;
  choices.append(index);
  choices.resize(ot_num);
  auto base_ot = MockRots(ot_num, choices);  // mock many base OTs

  std::vector<uint128_t> send_out(n);
  std::vector<uint128_t> recv_out(n);

  std::future<void> receiver = std::async([&] {
    auto recv_buf = lctxs[0]->Recv(lctxs[0]->NextRank(), "SGRR_OTE:RECV-CORR");
    YACL_ENFORCE(recv_buf.size() ==
                 static_cast<int64_t>(SgrrOtExtHelper(n, true)));
    SgrrOtExtRecv_fixed_index(
        std::move(base_ot.recv), n, absl::MakeSpan(recv_out),
        absl::MakeSpan(recv_buf.data<const uint8_t>(), recv_buf.size()), true);
  });
  std::future<void> sender = std::async([&] {
    auto send_buf = Buffer(SgrrOtExtHelper(n, true));
    SgrrOtExtSend_fixed_index(
        std::move(base_ot.send), n, absl::MakeSpan(send_out),
        absl::MakeSpan(send_buf.data<uint8_t>(), send_buf.size()), true);
    lctxs[1]->SendAsync(lctxs[1]->NextRank(), ByteContainerView(send_buf),
                        "SGRR_OTE:SEND-CORR");
  });
  sender.get();
  receiver.get();

  for (size_t i = 0; i < n; ++i) {
    if (index != i) {
      EXPECT_NE(recv_out[i], 0);
      EXPECT_EQ(send_out[i], recv_out[i]);
    } else {
      EXPECT_EQ(0, recv_out[i]);
    }
  }
}

INSTANTIATE_TEST_SUITE_P(Works_Instances, SgrrParamTest,
                         testing::Values(TestParams{4}, TestParams{5},  //
                                         TestParams{7},                 //
                                         TestParams{1024},              //
                                         TestParams{1 << 10},           //
                                         TestParams{1 << 15}));

// Edge Case
// n should be greater than 1
TEST(SgrrEdgeTest, Work) {
  size_t n = 1;

  auto index = RandInRange(n);
  auto lctxs = link::test::SetupWorld(2);
  auto base_ot = MockRots(1);  // mock many base OTs

  std::vector<uint128_t> send_out(n);
  std::vector<uint128_t> recv_out(n);

  std::future<void> receiver = std::async([&] {
    ASSERT_THROW(SgrrOtExtRecv(lctxs[0], std::move(base_ot.recv), n, index,
                               absl::MakeSpan(recv_out), false),
                 ::yacl::Exception);
    ASSERT_THROW(SgrrOtExtRecv(lctxs[0], std::move(base_ot.recv), n, index,
                               absl::MakeSpan(recv_out), true),
                 ::yacl::Exception);
  });
  std::future<void> sender = std::async([&] {
    ASSERT_THROW(SgrrOtExtSend(lctxs[1], std::move(base_ot.send), n,
                               absl::MakeSpan(send_out), false),
                 ::yacl::Exception);
    ASSERT_THROW(SgrrOtExtSend(lctxs[1], std::move(base_ot.send), n,
                               absl::MakeSpan(send_out), true),
                 ::yacl::Exception);
  });
  sender.get();
  receiver.get();
}

}  // namespace yacl::crypto
