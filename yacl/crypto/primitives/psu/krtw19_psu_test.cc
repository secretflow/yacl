// Copyright 2024 zhangwfjh
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

#include "yacl/crypto/primitives/psu/krtw19_psu.h"

#include <future>
#include <iostream>
#include <set>
#include <string>

#include "gtest/gtest.h"

#include "yacl/base/exception.h"
#include "yacl/crypto/base/hash/hash_utils.h"
#include "yacl/crypto/utils/secparam.h"
#include "yacl/link/test_util.h"

struct TestParams {
  std::vector<uint128_t> items_a;
  std::vector<uint128_t> items_b;
};

namespace yacl::crypto {

class KrtwPsuTest : public testing::TestWithParam<TestParams> {};

TEST_P(KrtwPsuTest, Works) {
  auto params = GetParam();
  const int kWorldSize = 2;
  auto contexts = yacl::link::test::SetupWorld(kWorldSize);

  std::future<void> krtwpsu_sender =
      std::async([&] { return KrtwPsuSend(contexts[0], params.items_a); });
  std::future<std::vector<uint128_t>> krtwpsu_receiver =
      std::async([&] { return KrtwPsuRecv(contexts[1], params.items_b); });

  krtwpsu_sender.get();
  auto psu_result = krtwpsu_receiver.get();
  std::sort(psu_result.begin(), psu_result.end());

  std::set<uint128_t> union_set;
  union_set.insert(params.items_a.begin(), params.items_a.end());
  union_set.insert(params.items_b.begin(), params.items_b.end());
  std::vector<uint128_t> union_vec(union_set.begin(), union_set.end());

  EXPECT_EQ(psu_result, union_vec);
}

std::vector<uint128_t> CreateRangeItems(size_t begin, size_t size) {
  std::vector<uint128_t> ret;
  for (size_t i = 0; i < size; i++) {
    ret.push_back(Blake3_128(std::to_string(begin + i)));
  }
  return ret;
}

INSTANTIATE_TEST_SUITE_P(
    Works_Instances, KrtwPsuTest,
    testing::Values(
        TestParams{{}, {}},                 //
        TestParams{{}, {Blake3_128("a")}},  //
        TestParams{{Blake3_128("a")}, {}},  //
        // No overlap
        TestParams{CreateRangeItems(0, 1024), CreateRangeItems(1024, 1024)},  //
        // Partial overlap
        TestParams{CreateRangeItems(0, 1024), CreateRangeItems(512, 1024)},  //
        // Complete overlap
        TestParams{CreateRangeItems(0, 1024), CreateRangeItems(0, 1024)}  //
        ));

}  // namespace yacl::crypto
