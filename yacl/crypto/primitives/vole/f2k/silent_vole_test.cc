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

#include "yacl/crypto/primitives/vole/f2k/silent_vole.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <future>
#include <thread>
#include <utility>
#include <vector>

#include "yacl/base/int128.h"
#include "yacl/link/test_util.h"
#include "yacl/math/f2k/f2k.h"

namespace yacl::crypto {

struct TestParams {
  CodeType codetype;
  size_t num;
};

class VoleTest : public ::testing::TestWithParam<TestParams> {};

// VOLE over GF(2^64) x GF(2^64)
TEST_P(VoleTest, SlientVole_GF64_Test) {
  auto lctxs = link::test::SetupWorld(2);  // setup network

  const auto codetype = GetParam().codetype;
  const uint64_t vole_num = GetParam().num;

  std::vector<uint64_t> a(vole_num);
  std::vector<uint64_t> b(vole_num);
  std::vector<uint64_t> c(vole_num);
  uint64_t delta = 0;

  auto sender = std::async([&] {
    auto sv_sender = SilentVoleSender(codetype);
    sv_sender.Send(lctxs[0], absl::MakeSpan(c));
    delta = sv_sender.GetDelta64();
  });

  auto receiver = std::async([&] {
    auto sv_receiver = SilentVoleReceiver(codetype);
    sv_receiver.Recv(lctxs[1], absl::MakeSpan(a), absl::MakeSpan(b));
  });

  sender.get();
  receiver.get();

  for (uint64_t i = 0; i < vole_num; ++i) {
    EXPECT_EQ(GfMul64(a[i], delta) ^ b[i], c[i]);
  }
}

// VOLE over GF(2^128) x GF(2^128)
TEST_P(VoleTest, SlientVole_GF128_Test) {
  auto lctxs = link::test::SetupWorld(2);  // setup network

  const auto codetype = GetParam().codetype;
  const uint64_t vole_num = GetParam().num;

  std::vector<uint128_t> a(vole_num);
  std::vector<uint128_t> b(vole_num);
  std::vector<uint128_t> c(vole_num);
  uint128_t delta = 0;

  auto sender = std::async([&] {
    auto sv_sender = SilentVoleSender(codetype);
    sv_sender.Send(lctxs[0], absl::MakeSpan(c));
    delta = sv_sender.GetDelta();
  });

  auto receiver = std::async([&] {
    auto sv_receiver = SilentVoleReceiver(codetype);
    sv_receiver.Recv(lctxs[1], absl::MakeSpan(a), absl::MakeSpan(b));
  });

  sender.get();
  receiver.get();

  for (uint64_t i = 0; i < vole_num; ++i) {
    EXPECT_EQ(GfMul128(a[i], delta) ^ b[i], c[i]);
  }
}

// subfield VOLE over GF(2^64) x GF(2^128)
TEST_P(VoleTest, SlientVole_GF64xGF128_Test) {
  auto lctxs = link::test::SetupWorld(2);  // setup network

  const auto codetype = GetParam().codetype;
  const uint64_t vole_num = GetParam().num;

  std::vector<uint64_t> a(vole_num);
  std::vector<uint128_t> b(vole_num);
  std::vector<uint128_t> c(vole_num);
  uint128_t delta = 0;

  auto sender = std::async([&] {
    auto sv_sender = SilentVoleSender(codetype);
    sv_sender.SfSend(lctxs[0], absl::MakeSpan(c));
    delta = sv_sender.GetDelta();
  });

  auto receiver = std::async([&] {
    auto sv_receiver = SilentVoleReceiver(codetype);
    sv_receiver.SfRecv(lctxs[1], absl::MakeSpan(a), absl::MakeSpan(b));
  });

  sender.get();
  receiver.get();

  for (uint64_t i = 0; i < vole_num; ++i) {
    auto ai = yacl::MakeUint128(0, a[i]);
    EXPECT_EQ(GfMul128(ai, delta) ^ b[i], c[i]);
  }
}

INSTANTIATE_TEST_SUITE_P(
    Works_Instances, VoleTest,
    testing::Values(TestParams{CodeType::Silver5, 64},  // edge test
                    TestParams{CodeType::Silver5, 1 << 10},
                    TestParams{CodeType::Silver5, 1 << 14},
                    TestParams{CodeType::Silver5, 1 << 18},
                    TestParams{CodeType::Silver11, 64},  // edge test
                    TestParams{CodeType::Silver11, 1 << 10},
                    TestParams{CodeType::Silver11, 1 << 14},
                    TestParams{CodeType::Silver11, 1 << 18},
                    TestParams{CodeType::ExAcc7, 64},  // edge test
                    TestParams{CodeType::ExAcc7, 1 << 10},
                    TestParams{CodeType::ExAcc7, 1 << 14},
                    TestParams{CodeType::ExAcc7, 1 << 18},
                    TestParams{CodeType::ExAcc11, 64},  // edge test
                    TestParams{CodeType::ExAcc11, 1 << 10},
                    TestParams{CodeType::ExAcc11, 1 << 14},
                    TestParams{CodeType::ExAcc11, 1 << 18},
                    TestParams{CodeType::ExAcc21, 64},  // edge test
                    TestParams{CodeType::ExAcc21, 1 << 10},
                    TestParams{CodeType::ExAcc21, 1 << 14},
                    TestParams{CodeType::ExAcc21, 1 << 18},
                    TestParams{CodeType::ExAcc40, 64},  // edge test
                    TestParams{CodeType::ExAcc40, 1 << 10},
                    TestParams{CodeType::ExAcc40, 1 << 14},
                    TestParams{CodeType::ExAcc40, 1 << 18}));

}  // namespace yacl::crypto