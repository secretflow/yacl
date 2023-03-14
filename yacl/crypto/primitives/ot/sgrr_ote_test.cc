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

#include <future>
#include <thread>
#include <utility>
#include <vector>

#include "fmt/format.h"
#include "gtest/gtest.h"

#include "yacl/base/exception.h"
#include "yacl/crypto/primitives/ot/ot_store.h"
#include "yacl/crypto/utils/math.h"
#include "yacl/link/test_util.h"

namespace yacl::crypto {

struct TestParams {
  unsigned n;
};

class SgrrParamTest : public ::testing::TestWithParam<TestParams> {};

TEST_P(SgrrParamTest, Works) {
  size_t n = GetParam().n;

  auto index = RandInRange(n);
  auto lctxs = link::test::SetupWorld(2);
  auto base_ot = MockRots(Log2Ceil(n));  // mock many base OTs

  std::vector<uint128_t> send_out(n);
  std::vector<uint128_t> recv_out(n);

  std::future<void> sender = std::async([&] {
    SgrrOtExtRecv(lctxs[0], std::move(base_ot.recv), n, index,
                  absl::MakeSpan(recv_out));
  });
  std::future<void> receiver = std::async([&] {
    SgrrOtExtSend(lctxs[1], std::move(base_ot.send), n,
                  absl::MakeSpan(send_out));
  });
  sender.get();
  receiver.get();

  EXPECT_EQ(send_out.size(), n);
  EXPECT_EQ(recv_out.size(), n);

  for (size_t i = 0; i < n; ++i) {
    if (index != i) {
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

}  // namespace yacl::crypto
