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

#include "yacl/crypto/primitives/vole/f2k/sparse_vole.h"

#include <gtest/gtest.h>

#include <future>
#include <thread>
#include <utility>
#include <vector>

#include "sparse_vole.h"

#include "yacl/base/exception.h"
#include "yacl/crypto/utils/rand.h"
#include "yacl/link/test_util.h"
#include "yacl/math/f2k/f2k.h"
#include "yacl/math/gadget.h"

namespace yacl::crypto {

struct TestParams {
  size_t num;
};

struct TestParams2 {
  size_t num;
  size_t index_num;
};

class SpVoleTest : public ::testing::TestWithParam<TestParams> {};
class MpVoleTest : public ::testing::TestWithParam<TestParams2> {};

TEST_P(SpVoleTest, SpVoleWork) {
  auto lctxs = link::test::SetupWorld(2);  // setup network
  const uint64_t num = GetParam().num;
  auto cot = MockCots(math::Log2Ceil(num), FastRandU128());

  // auto delta = rot.recv.CopyChoice().data()[0];

  std::vector<uint128_t> v(num);
  std::vector<uint128_t> w(num);

  uint128_t single_v = FastRandU128();
  uint128_t single_w = FastRandU128();
  uint32_t index = FastRandU64() % num;

  auto sender = std::async([&] {
    SpVoleSend(lctxs[0], cot.send, num, single_w, absl::MakeSpan(w));
  });

  auto receiver = std::async([&] {
    SpVoleRecv(lctxs[1], cot.recv, num, index, single_v, absl::MakeSpan(v));
  });

  sender.get();
  receiver.get();

  for (uint64_t i = 0; i < num; ++i) {
    if (i == index) {
      EXPECT_EQ(v[i] ^ w[i], single_v ^ single_w);
    } else {
      EXPECT_EQ(v[i], w[i]);
    }
  }
}

TEST_P(MpVoleTest, MpVoleWork) {
  auto lctxs = link::test::SetupWorld(2);  // setup network
  const uint64_t num = GetParam().num;
  const uint64_t index_num = GetParam().index_num;

  MpVoleParam param(index_num, num);
  param.GenIndexes();

  auto cot = MockCots(param.require_ot_num_, FastRandU128());

  std::vector<uint128_t> s_output(num);
  std::vector<uint128_t> r_output(num);

  auto v = RandVec<uint128_t>(index_num);
  auto w = RandVec<uint128_t>(index_num);

  auto sender = std::async([&] {
    MpVoleSend(lctxs[0], cot.send, param, absl::MakeSpan(w),
               absl::MakeSpan(s_output));
  });

  auto receiver = std::async([&] {
    MpVoleRecv(lctxs[1], cot.recv, param, absl::MakeSpan(v),
               absl::MakeSpan(r_output));
  });

  sender.get();
  receiver.get();

  std::set<uint32_t> indexes;
  for (size_t i = 0; i < param.noise_num_; ++i) {
    indexes.insert(i * param.sp_vole_size_ + param.indexes_[i]);
  }
  uint64_t j = 0;
  uint64_t i = 0;
  for (; i < num && j < index_num; ++i) {
    if (s_output[i] != r_output[i]) {
      EXPECT_EQ(v[j] ^ w[j], s_output[i] ^ r_output[i]);
      EXPECT_TRUE(indexes.count(i));
      j++;
    }
  }
  for (; i < num; ++i) {
    EXPECT_EQ(s_output[i], r_output[i]);
  }
}

TEST_P(MpVoleTest, MpVole128_fixed_index_Work) {
  auto lctxs = link::test::SetupWorld(2);  // setup network
  const uint64_t num = GetParam().num;
  const uint64_t index_num = GetParam().index_num;

  MpVoleParam param(index_num, num);

  auto choices = RandBits<dynamic_bitset<uint128_t>>(param.require_ot_num_);
  // dynamic_bitset<uint128_t> choices;
  // generate the choices for MpVole
  param.GenIndexes();
  uint64_t pos = 0;
  for (size_t i = 0; i < param.noise_num_; ++i) {
    auto this_size = (i == param.noise_num_ - 1)
                         ? math::Log2Ceil(param.last_sp_vole_size_)
                         : math::Log2Ceil(param.sp_vole_size_);
    uint32_t bound = 1 << this_size;
    for (uint32_t mask = 1; mask < bound; mask <<= 1) {
      choices.set(pos, param.indexes_[i] & mask);
      ++pos;
    }
  }

  YACL_ENFORCE(pos == param.require_ot_num_);

  auto cot = MockCots(param.require_ot_num_, FastRandU128(), choices);

  std::vector<uint128_t> s_output(num);
  std::vector<uint128_t> r_output(num);

  auto v = RandVec<uint128_t>(index_num);
  auto w = RandVec<uint128_t>(index_num);

  auto sender = std::async([&] {
    MpVoleSend_fixed_index(lctxs[0], cot.send, param, absl::MakeSpan(w),
                           absl::MakeSpan(s_output));
  });

  auto receiver = std::async([&] {
    MpVoleRecv_fixed_index(lctxs[1], cot.recv, param, absl::MakeSpan(v),
                           absl::MakeSpan(r_output));
  });

  sender.get();
  receiver.get();

  std::set<uint32_t> indexes;
  for (size_t i = 0; i < param.noise_num_; ++i) {
    indexes.insert(i * param.sp_vole_size_ + param.indexes_[i]);
  }
  uint64_t j = 0;
  uint64_t i = 0;
  for (; i < num && j < index_num; ++i) {
    if (s_output[i] != r_output[i]) {
      EXPECT_EQ(v[j] ^ w[j], s_output[i] ^ r_output[i]);
      EXPECT_TRUE(indexes.count(i));
      j++;
    }
  }
  for (; i < num; ++i) {
    EXPECT_EQ(s_output[i], r_output[i]);
  }
}

TEST_P(MpVoleTest, MpVole64_fixed_index_Work) {
  auto lctxs = link::test::SetupWorld(2);  // setup network
  const uint64_t num = GetParam().num;
  const uint64_t index_num = GetParam().index_num;

  MpVoleParam param(index_num, num);

  auto choices = RandBits<dynamic_bitset<uint128_t>>(param.require_ot_num_);
  // dynamic_bitset<uint128_t> choices;
  // generate the choices for MpVole
  param.GenIndexes();
  uint64_t pos = 0;
  for (size_t i = 0; i < param.noise_num_; ++i) {
    auto this_size = (i == param.noise_num_ - 1)
                         ? math::Log2Ceil(param.last_sp_vole_size_)
                         : math::Log2Ceil(param.sp_vole_size_);
    uint32_t bound = 1 << this_size;
    for (uint32_t mask = 1; mask < bound; mask <<= 1) {
      choices.set(pos, param.indexes_[i] & mask);
      ++pos;
    }
  }

  YACL_ENFORCE(pos == param.require_ot_num_);

  auto cot = MockCots(param.require_ot_num_, FastRandU128(), choices);

  std::vector<uint64_t> s_output(num);
  std::vector<uint64_t> r_output(num);

  auto v = RandVec<uint64_t>(index_num);
  auto w = RandVec<uint64_t>(index_num);

  auto sender = std::async([&] {
    MpVoleSend_fixed_index(lctxs[0], cot.send, param, absl::MakeSpan(w),
                           absl::MakeSpan(s_output));
  });

  auto receiver = std::async([&] {
    MpVoleRecv_fixed_index(lctxs[1], cot.recv, param, absl::MakeSpan(v),
                           absl::MakeSpan(r_output));
  });

  sender.get();
  receiver.get();

  std::set<uint32_t> indexes;
  for (size_t i = 0; i < param.noise_num_; ++i) {
    indexes.insert(i * param.sp_vole_size_ + param.indexes_[i]);
  }
  uint64_t j = 0;
  uint64_t i = 0;
  for (; i < num && j < index_num; ++i) {
    if (s_output[i] != r_output[i]) {
      EXPECT_EQ(v[j] ^ w[j], s_output[i] ^ r_output[i]);
      EXPECT_TRUE(indexes.count(i));
      j++;
    }
  }
  for (; i < num; ++i) {
    EXPECT_EQ(s_output[i], r_output[i]);
  }
}

INSTANTIATE_TEST_SUITE_P(Works_Instances, SpVoleTest,
                         testing::Values(TestParams{4}, TestParams{5},  //
                                         TestParams{7},                 //
                                         TestParams{1 << 8},
                                         TestParams{1 << 10}));

INSTANTIATE_TEST_SUITE_P(Works_Instances, MpVoleTest,
                         testing::Values(TestParams2{4, 2},
                                         TestParams2{5, 2},  //
                                         TestParams2{7, 2},  //
                                         TestParams2{1 << 8, 64},
                                         TestParams2{1 << 10, 257},
                                         TestParams2{1 << 20, 1024}));

}  // namespace yacl::crypto
