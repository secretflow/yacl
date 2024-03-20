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

#include "mpfss.h"

#include <gtest/gtest.h>

#include <future>
#include <set>
#include <thread>
#include <utility>
#include <vector>

#include "yacl/base/exception.h"
#include "yacl/crypto/rand/rand.h"
#include "yacl/link/test_util.h"
#include "yacl/math/f2k/f2k.h"
#include "yacl/math/gadget.h"

namespace yacl::crypto {

struct TestParam {
  size_t num;
  size_t index_num;
};

class Mpfss64Test
    : public ::testing::TestWithParam<
          std::tuple<bool /* GF(2^128) or Ring(2^128) */,
                     bool /* fixed index or selected index */, TestParam>> {};

class Mpfss128Test
    : public ::testing::TestWithParam<
          std::tuple<bool /* GF(2^128) or Ring(2^128) */,
                     bool /* fixed index or selected index */, TestParam>> {};

template <typename T>
MpfssOp<T> CreateMpfssOp(bool xor_mode) {
  MpfssOp<T> ret;
  if (xor_mode) {
    ret = MakeMpfssOp<T>(std::bit_xor<T>(), std::bit_xor<T>());
  } else {
    ret = MakeMpfssOp<T>(std::plus<T>(), std::minus<T>());
  }
  return ret;
}

TEST_P(Mpfss64Test, Work) {
  auto lctxs = link::test::SetupWorld(2);  // setup network
  const auto op = CreateMpfssOp<uint64_t>(std::get<0>(GetParam()));
  const auto is_fixed = std::get<1>(GetParam());
  const uint64_t num = std::get<2>(GetParam()).num;
  const uint64_t index_num = std::get<2>(GetParam()).index_num;

  MpFssParam param(index_num, num);
  param.GenIndexes();

  auto choices = RandBits<dynamic_bitset<uint128_t>>(param.require_ot_num_);
  if (is_fixed) {
    choices = param.GenChoices();
  }
  auto cot = MockCots(param.require_ot_num_, FastRandU128(), choices);

  std::vector<uint64_t> s_output(num);
  std::vector<uint64_t> r_output(num);

  auto w = RandVec<uint64_t>(index_num);

  auto sender = std::async([&] {
    if (is_fixed) {
      MpfssSend_fixed_index(lctxs[0], cot.send, param, absl::MakeSpan(w),
                            absl::MakeSpan(s_output), op);
    } else {
      MpfssSend(lctxs[0], cot.send, param, absl::MakeSpan(w),
                absl::MakeSpan(s_output), op);
    }
  });

  auto receiver = std::async([&] {
    if (is_fixed) {
      MpfssRecv_fixed_index(lctxs[1], cot.recv, param, absl::MakeSpan(r_output),
                            op);
    } else {
      MpfssRecv(lctxs[1], cot.recv, param, absl::MakeSpan(r_output), op);
    }
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
      EXPECT_EQ(w[j], op.sub(s_output[i], r_output[i]));
      EXPECT_TRUE(indexes.count(i));
      j++;
    }
  }
  for (; i < num; ++i) {
    EXPECT_EQ(s_output[i], r_output[i]);
  }
  EXPECT_EQ(j, index_num);
}

TEST_P(Mpfss128Test, Work) {
  auto lctxs = link::test::SetupWorld(2);  // setup network
  const auto op = CreateMpfssOp<uint128_t>(std::get<0>(GetParam()));
  const auto is_fixed = std::get<1>(GetParam());
  const uint64_t num = std::get<2>(GetParam()).num;
  const uint64_t index_num = std::get<2>(GetParam()).index_num;

  MpFssParam param(index_num, num);
  param.GenIndexes();

  auto choices = RandBits<dynamic_bitset<uint128_t>>(param.require_ot_num_);
  if (is_fixed) {
    choices = param.GenChoices();
  }
  auto cot = MockCots(param.require_ot_num_, FastRandU128(), choices);

  std::vector<uint128_t> s_output(num);
  std::vector<uint128_t> r_output(num);

  auto w = RandVec<uint128_t>(index_num);

  auto sender = std::async([&] {
    if (is_fixed) {
      MpfssSend_fixed_index(lctxs[0], cot.send, param, absl::MakeSpan(w),
                            absl::MakeSpan(s_output), op);
    } else {
      MpfssSend(lctxs[0], cot.send, param, absl::MakeSpan(w),
                absl::MakeSpan(s_output), op);
    }
  });

  auto receiver = std::async([&] {
    if (is_fixed) {
      MpfssRecv_fixed_index(lctxs[1], cot.recv, param, absl::MakeSpan(r_output),
                            op);
    } else {
      MpfssRecv(lctxs[1], cot.recv, param, absl::MakeSpan(r_output), op);
    }
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
      EXPECT_EQ(w[j], op.sub(s_output[i], r_output[i]));
      EXPECT_TRUE(indexes.count(i));
      j++;
    }
  }
  for (; i < num; ++i) {
    EXPECT_EQ(s_output[i], r_output[i]);
  }
  EXPECT_EQ(j, index_num);
}

INSTANTIATE_TEST_SUITE_P(
    VoleInternal, Mpfss64Test,
    testing::Combine(
        testing::Values(true,  // true for xor_mode, GF(2^64)
                        false  // false for add_mode, Ring(2^64)
                        ),
        testing::Values(true,  // true for fix index (determined by OT)
                        false  // false for selected index
                        ),
        testing::Values(TestParam{4, 2},  // edge
                        TestParam{5, 2},  // edge
                        TestParam{7, 2},  // edge
                        TestParam{1 << 8, 64}, TestParam{1 << 10, 257},
                        TestParam{1 << 20, 1024})),
    [](const testing::TestParamInfo<Mpfss64Test::ParamType>& p) {
      return fmt::format("{}_{}_t{}xn{}",
                         std::get<1>(p.param) ? "FixedIndex" : "SelectedIndex",
                         std::get<0>(p.param) ? "XOR" : "ADD",
                         std::get<2>(p.param).index_num,
                         std::get<2>(p.param).num);
    });

INSTANTIATE_TEST_SUITE_P(
    VoleInternal, Mpfss128Test,
    testing::Combine(
        testing::Values(true,  // true for xor_mode, GF(2^128)
                        false  // false for add_mode, Ring(2^128)
                        ),
        testing::Values(true,  // true for fix index (determined by OT)
                        false  // false for selected index
                        ),
        testing::Values(TestParam{4, 2},  // edge
                        TestParam{5, 2},  // edge
                        TestParam{7, 2},  // edge
                        TestParam{1 << 8, 64}, TestParam{1 << 10, 257},
                        TestParam{1 << 20, 1024})),
    [](const testing::TestParamInfo<Mpfss128Test::ParamType>& p) {
      return fmt::format("{}_{}_t{}xn{}",
                         std::get<1>(p.param) ? "FixedIndex" : "SelectedIndex",
                         std::get<0>(p.param) ? "XOR" : "ADD",
                         std::get<2>(p.param).index_num,
                         std::get<2>(p.param).num);
    });

}  // namespace yacl::crypto
