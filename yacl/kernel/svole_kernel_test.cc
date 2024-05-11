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

#include "yacl/kernel/svole_kernel.h"

#include <gtest/gtest.h>

#include <future>
#include <vector>

#include "gtest/gtest.h"

#include "yacl/link/test_util.h"

namespace yacl::crypto {

struct TestParams {
  size_t num_vole;
  int threads = 1;
  // int step_size;
};

class SVoleTest : public ::testing::TestWithParam<TestParams> {};

TEST(SVoleTest, SingleThreadShouldWork) {
  auto lctxs = link::test::SetupWorld(2);

  const size_t num_vole = 1 << 10;

  uint128_t delta = 0;
  std::vector<uint64_t> a(num_vole);
  std::vector<uint128_t> b(num_vole);
  std::vector<uint128_t> c(num_vole);
  SVoleKernel kernel0(SVoleKernel::Role::Sender);
  SVoleKernel kernel1(SVoleKernel::Role::Receiver);

  // WHEN
  auto sender = std::async([&] {
    kernel0.init(lctxs[0]);
    kernel0.eval(lctxs[0], &delta, absl::MakeSpan(c));
  });
  auto receiver = std::async([&] {
    kernel1.init(lctxs[1]);
    kernel1.eval(lctxs[1], absl::MakeSpan(a), absl::MakeSpan(b));
  });
  sender.get();
  receiver.get();

  for (uint64_t i = 0; i < num_vole; ++i) {
    EXPECT_EQ(math::GfMul(a[i], delta) ^ b[i], c[i]);
  }
}

TEST_P(SVoleTest, MultiThreadShouldWork) {
  auto lctxs = link::test::SetupWorld(2);

  const size_t num_vole = GetParam().num_vole;
  const size_t threads = GetParam().threads;

  uint128_t delta = 0;
  std::vector<uint64_t> a(num_vole);
  std::vector<uint128_t> b(num_vole);
  std::vector<uint128_t> c(num_vole);
  SVoleKernel kernel0(SVoleKernel::Role::Sender);
  SVoleKernel kernel1(SVoleKernel::Role::Receiver);

  // WHEN
  auto sender = std::async([&] {
    kernel0.init(lctxs[0]);
    kernel0.eval_multithread(lctxs[0], &delta, absl::MakeSpan(c), threads);
  });
  auto receiver = std::async([&] {
    kernel1.init(lctxs[1]);
    kernel1.eval_multithread(lctxs[1], absl::MakeSpan(a), absl::MakeSpan(b),
                             threads);
  });
  sender.get();
  receiver.get();

  for (uint64_t i = 0; i < num_vole; ++i) {
    EXPECT_EQ(math::GfMul(a[i], delta) ^ b[i], c[i]);
    // if ((math::GfMul(a[i], delta) ^ b[i]) != c[i]) {
    //   SPDLOG_INFO("ERROR: a[{}]={}, delta={}, b[{}]={}, c[{}]={}", i, a[i],
    //               delta, i, b[i], i, c[i]);
    //   SPDLOG_INFO("ERROR: expect c[{}]={}, but c[{}]={}", i,
    //               math::GfMul(a[i], delta) ^ b[i], i, c[i]);
    //   break;
    // }
  }
}

INSTANTIATE_TEST_SUITE_P(Works_Instances, SVoleTest,
                         testing::Values(TestParams{1 << 10, 1},  //
                                         TestParams{1 << 10, 2},  //
                                         TestParams{1 << 10, 3},  //
                                         TestParams{1 << 10, 4}   //
                                         ));

}  // namespace yacl::crypto
