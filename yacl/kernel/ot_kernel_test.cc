// Copyright 2024 Ant Group Co., Ltd.
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

#include "yacl/kernel/ot_kernel.h"

#include <gtest/gtest.h>

#include <future>
#include <vector>

#include "gtest/gtest.h"

#include "yacl/kernel/type/ot_store_utils.h"
#include "yacl/link/test_util.h"

namespace yacl::crypto {

struct TestParams {
  size_t num_ot;
  OtKernel::ExtAlgorithm ext_algorithm;
};

class OtTest : public ::testing::TestWithParam<TestParams> {};

TEST_P(OtTest, EvalCotRandomChoice) {
  auto lctxs = link::test::SetupWorld(2);

  const size_t num_ot = GetParam().num_ot;
  const auto ext_algorithm = GetParam().ext_algorithm;

  OtSendStore ot_send(num_ot, OtStoreType::Compact);  // placeholder
  OtRecvStore ot_recv(num_ot, OtStoreType::Compact);  // placeholder

  OtKernel kernel0(OtKernel::Role::Sender, ext_algorithm);
  OtKernel kernel1(OtKernel::Role::Receiver, ext_algorithm);

  // WHEN
  auto sender = std::async([&] {
    kernel0.init(lctxs[0]);
    kernel0.eval_cot_random_choice(lctxs[0], num_ot, &ot_send);
  });
  auto receiver = std::async([&] {
    kernel1.init(lctxs[1]);
    kernel1.eval_cot_random_choice(lctxs[1], num_ot, &ot_recv);
  });
  sender.get();
  receiver.get();

  EXPECT_EQ(ot_send.Type(), OtStoreType::Compact);
  EXPECT_EQ(ot_recv.Type(), OtStoreType::Compact);

  for (uint64_t i = 0; i < num_ot; ++i) {
    // correctness of ot
    EXPECT_EQ(ot_send.GetBlock(i, ot_recv.GetChoice(i)), ot_recv.GetBlock(i));

    // generated ot messages should not equal
    EXPECT_NE(ot_send.GetBlock(i, 1 - ot_recv.GetChoice(i)),
              ot_recv.GetBlock(i));

    // generated choice should be random
    // ...
  }
}

TEST_P(OtTest, EvalRot) {
  auto lctxs = link::test::SetupWorld(2);

  const size_t num_ot = GetParam().num_ot;
  const auto ext_algorithm = GetParam().ext_algorithm;

  OtSendStore ot_send(num_ot, OtStoreType::Normal);  // placeholder
  OtRecvStore ot_recv(num_ot, OtStoreType::Normal);  // placeholder

  OtKernel kernel0(OtKernel::Role::Sender, ext_algorithm);
  OtKernel kernel1(OtKernel::Role::Receiver, ext_algorithm);

  // WHEN
  auto sender = std::async([&] {
    kernel0.init(lctxs[0]);
    kernel0.eval_rot(lctxs[0], num_ot, &ot_send);
  });
  auto receiver = std::async([&] {
    kernel1.init(lctxs[1]);
    kernel1.eval_rot(lctxs[1], num_ot, &ot_recv);
  });
  sender.get();
  receiver.get();

  for (uint64_t i = 0; i < num_ot; ++i) {
    EXPECT_EQ(ot_send.GetBlock(i, ot_recv.GetChoice(i)), ot_recv.GetBlock(i));
    EXPECT_NE(ot_send.GetBlock(i, 1 - ot_recv.GetChoice(i)),
              ot_recv.GetBlock(i));
  }
}

INSTANTIATE_TEST_SUITE_P(
    Works_Instances, OtTest,
    testing::Values(TestParams{1 << 20, OtKernel::ExtAlgorithm::Ferret},
                    TestParams{1 << 20, OtKernel::ExtAlgorithm::SoftSpoken}  //
                    ));
}  // namespace yacl::crypto
