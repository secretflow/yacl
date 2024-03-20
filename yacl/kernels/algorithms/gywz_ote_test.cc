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

#include "yacl/kernels/algorithms/gywz_ote.h"

#include <future>
#include <thread>

#include "fmt/format.h"
#include "gtest/gtest.h"

#include "yacl/base/exception.h"
#include "yacl/crypto/rand/rand.h"
#include "yacl/kernels/algorithms/ot_store.h"
#include "yacl/link/test_util.h"
#include "yacl/math/gadget.h"

namespace yacl::crypto {

struct TestParams {
  unsigned n;
};

class GywzParamTest : public ::testing::TestWithParam<TestParams> {};

TEST_P(GywzParamTest, CotWork) {
  size_t n = GetParam().n;

  auto index = RandInRange(n);
  auto lctxs = link::test::SetupWorld(2);
  uint128_t delta = SecureRandSeed();
  auto base_ot = MockCots(math::Log2Ceil(n), delta);  // mock many base OTs

  std::vector<uint128_t> send_out(n);
  std::vector<uint128_t> recv_out(n);

  std::future<void> sender = std::async([&] {
    GywzOtExtRecv(lctxs[0], base_ot.recv, n, index, absl::MakeSpan(recv_out));
  });
  std::future<void> receiver = std::async([&] {
    GywzOtExtSend(lctxs[1], base_ot.send, n, absl::MakeSpan(send_out));
  });
  sender.get();
  receiver.get();

  EXPECT_EQ(send_out.size(), n);
  EXPECT_EQ(recv_out.size(), n);

  for (size_t i = 0; i < n; ++i) {
    EXPECT_NE(recv_out[i], 0);
    EXPECT_NE(send_out[i], 0);
    if (index != i) {
      EXPECT_EQ(send_out[i], recv_out[i]);
    } else {
      EXPECT_EQ(send_out[i] ^ delta, recv_out[i]);
    }
  }
}

TEST_P(GywzParamTest, FerretSpCotWork) {
  size_t n = GetParam().n;

  auto lctxs = link::test::SetupWorld(2);

  auto base_ot = MockCompactOts(math::Log2Ceil(n));  // mock many base OTs
  auto delta = base_ot.send.GetDelta();

  // [Warning] Compact Cot doest not support CopyChoice.
  // TODO: fix it
  uint32_t index = 0;
  for (uint32_t i = 0; i < math::Log2Ceil(n); ++i) {
    index |= (base_ot.recv.GetChoice(i)) << i;
  }

  std::vector<uint128_t> send_out(n);
  std::vector<uint128_t> recv_out(n);

  std::future<void> sender = std::async([&] {
    GywzOtExtRecv_ferret(lctxs[0], base_ot.recv, n, absl::MakeSpan(recv_out));
  });
  std::future<void> receiver = std::async([&] {
    GywzOtExtSend_ferret(lctxs[1], base_ot.send, n, absl::MakeSpan(send_out));
  });
  sender.get();
  receiver.get();

  EXPECT_EQ(send_out.size(), n);
  EXPECT_EQ(recv_out.size(), n);

  for (size_t i = 0; i < n; ++i) {
    EXPECT_NE(recv_out[i], 0);
    EXPECT_NE(send_out[i], 0);
    if (index != i) {
      EXPECT_EQ(send_out[i], recv_out[i]);
    } else {
      EXPECT_EQ(send_out[i] ^ delta, recv_out[i]);
    }
  }
}

TEST_P(GywzParamTest, FixIndexSpCotWork) {
  size_t n = GetParam().n;

  auto lctxs = link::test::SetupWorld(2);

  uint128_t delta = SecureRandSeed();
  auto base_ot = MockCots(math::Log2Ceil(n), delta);  // mock many base OTs

  uint32_t index = base_ot.recv.CopyChoice().data()[0];

  std::vector<uint128_t> send_out(n);
  std::vector<uint128_t> recv_out(n);

  std::future<void> sender = std::async([&] {
    GywzOtExtRecv_fixed_index(lctxs[0], base_ot.recv, n,
                              absl::MakeSpan(recv_out));
  });
  std::future<void> receiver = std::async([&] {
    GywzOtExtSend_fixed_index(lctxs[1], base_ot.send, n,
                              absl::MakeSpan(send_out));
  });
  sender.get();
  receiver.get();

  EXPECT_EQ(send_out.size(), n);
  EXPECT_EQ(recv_out.size(), n);

  for (size_t i = 0; i < n; ++i) {
    EXPECT_NE(recv_out[i], 0);
    EXPECT_NE(send_out[i], 0);
    if (index != i) {
      EXPECT_EQ(send_out[i], recv_out[i]);
    } else {
      EXPECT_EQ(send_out[i] ^ delta, recv_out[i]);
    }
  }
}

INSTANTIATE_TEST_SUITE_P(TestWork, GywzParamTest,
                         testing::Values(TestParams{2},        // edge
                                         TestParams{3},        //
                                         TestParams{4},        //
                                         TestParams{5},        //
                                         TestParams{7},        //
                                         TestParams{1024},     //
                                         TestParams{1 << 10},  //
                                         TestParams{1 << 15}));

// Edge Case
// n should be greater than 1
TEST(GywzEdgeTest, Work) {
  size_t n = 1;

  auto index = RandInRange(n);
  auto lctxs = link::test::SetupWorld(2);
  uint128_t delta = SecureRandSeed();
  auto base_ot = MockCots(1, delta);  // mock many base OTs

  std::vector<uint128_t> send_out(n);
  std::vector<uint128_t> recv_out(n);

  std::future<void> sender = std::async([&] {
    ASSERT_THROW(GywzOtExtRecv(lctxs[0], base_ot.recv, n, index,
                               absl::MakeSpan(recv_out)),
                 ::yacl::Exception);
  });
  std::future<void> receiver = std::async([&] {
    ASSERT_THROW(
        GywzOtExtSend(lctxs[1], base_ot.send, n, absl::MakeSpan(send_out)),
        ::yacl::Exception);
  });
  sender.get();
  receiver.get();
}
}  // namespace yacl::crypto
