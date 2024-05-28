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

#include "examples/psu/krtw19_psu.h"

#include <algorithm>
#include <future>
#include <iostream>
#include <set>
#include <string>

#include "gtest/gtest.h"

#include "yacl/base/exception.h"
#include "yacl/crypto/hash/hash_utils.h"
#include "yacl/link/test_util.h"
#include "yacl/secparam.h"

struct TestParams {
  std::vector<uint128_t> items_a;
  std::vector<uint128_t> items_b;
};

namespace examples::psu {

class PolyTest : public testing ::TestWithParam<size_t> {};

TEST_P(PolyTest, Works) {
  auto size = GetParam();
  auto xs = yacl::crypto::RandVec<uint64_t>(size);
  auto ys = yacl::crypto::RandVec<uint64_t>(size);

  auto ceof = Interpolate(xs, ys);
  EXPECT_EQ(ceof.size(), size);
  for (size_t i = 0; i < size; ++i) {
    EXPECT_EQ(ys[i], Evaluate(ceof, xs[i]));
  }
}

INSTANTIATE_TEST_SUITE_P(Works_Instances, PolyTest,
                         testing::Values(10, 100, 1000, 10000));

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
    ret.push_back(yacl::crypto::Blake3_128(std::to_string(begin + i)));
  }
  return ret;
}

INSTANTIATE_TEST_SUITE_P(
    Works_Instances, KrtwPsuTest,
    testing::Values(
        TestParams{{}, {}},                               //
        TestParams{{}, {yacl::crypto::Blake3_128("a")}},  //
        TestParams{{yacl::crypto::Blake3_128("a")}, {}},  //
        // No overlap
        TestParams{CreateRangeItems(0, 1024), CreateRangeItems(1024, 1024)},  //
        // Partial overlap
        TestParams{CreateRangeItems(0, 1024), CreateRangeItems(512, 1024)},  //
        // Complete overlap
        TestParams{CreateRangeItems(0, 1024), CreateRangeItems(0, 1024)}  //
        ));

}  // namespace examples::psu
