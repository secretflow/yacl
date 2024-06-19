// Copyright 2019 Ant Group Co., Ltd.
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

#include "yacl/crypto/experimental/sync_drbg/sync_drbg.h"

#include <cstdint>
#include <future>
#include <memory>
#include <random>
#include <vector>

#include "absl/strings/escaping.h"
#include "gtest/gtest.h"

#include "yacl/link/test_util.h"

namespace yacl::crypto {

TEST(DrbgTest, DifferentDrbg) {
  /* GIVEN */
  auto drbg0 = SyncDrbg();
  auto drbg1 = SyncDrbg();
  Buffer buf0(10);
  Buffer buf1(10);

  /* WHEN */
  EXPECT_EQ(drbg0.Fill((char*)buf0.data(), buf0.size()), 1);
  EXPECT_EQ(drbg1.Fill((char*)buf1.data(), buf1.size()), 1);

  /* THEN */
  auto cmp = std::memcmp(buf0.data(), buf1.data(), buf0.size());
  EXPECT_NE(cmp, 0);

  /* debug */
  // SPDLOG_INFO("buf0 = {}", absl::BytesToHexString(buf0));
  // SPDLOG_INFO("buf1 = {}", absl::BytesToHexString(buf1));
}

TEST(DrbgTest, ReplayWork) {
  /* GIVEN */
  auto drbg0 = SyncDrbg();
  auto drbg1 = SyncDrbg();
  Buffer buf0(10);
  Buffer buf1(10);

  auto contexts = link::test::SetupWorld(2);

  /* WHEN */
  auto proc0 = std::async([&]() { drbg0.SendState(contexts[0], 1); });
  auto proc1 = std::async([&]() { drbg1.RecvState(contexts[1], 0); });
  proc0.get();
  proc1.get();

  /* THEN */
  EXPECT_EQ(drbg0.Fill((char*)buf0.data(), buf0.size()), 1);
  EXPECT_EQ(drbg1.Fill((char*)buf1.data(), buf1.size()), 1);
  auto cmp = std::memcmp(buf0.data(), buf1.data(), buf0.size());
  EXPECT_EQ(cmp, 0);

  /* debug */
  // SPDLOG_INFO("buf0 = {}", absl::BytesToHexString(buf0));
  // SPDLOG_INFO("buf1 = {}", absl::BytesToHexString(buf1));
}

TEST(DrbgTest, ForkWork) {
  /* GIVEN */
  auto drbg0 = SyncDrbg();
  Buffer buf0(10);
  Buffer buf1(10);

  /* WHEN */
  auto drbg1 = drbg0.Fork();

  /* THEN */
  EXPECT_EQ(drbg0.Fill((char*)buf0.data(), buf0.size()), 1);
  EXPECT_EQ(drbg1.Fill((char*)buf1.data(), buf1.size()), 1);
  auto cmp = std::memcmp(buf0.data(), buf1.data(), buf0.size());
  EXPECT_EQ(cmp, 0);

  /* debug */
  // SPDLOG_INFO("buf0 = {}", absl::BytesToHexString(buf0));
  // SPDLOG_INFO("buf1 = {}", absl::BytesToHexString(buf1));
}

TEST(DrbgTest, ReseedWork) {
  /* GIVEN */
  auto drbg0 = SyncDrbg();
  auto drbg1 = SyncDrbg();
  Buffer buf0(10);
  Buffer buf1(10);

  auto contexts = link::test::SetupWorld(2);

  /* WHEN */
  auto proc0 = std::async([&]() { drbg0.SendState(contexts[0], 1); });
  auto proc1 = std::async([&]() { drbg1.RecvState(contexts[1], 0); });
  proc0.get();
  proc1.get();

  drbg0.Reseed();

  /* THEN */
  EXPECT_EQ(drbg0.Fill((char*)buf0.data(), buf0.size()), 1);
  EXPECT_EQ(drbg1.Fill((char*)buf1.data(), buf1.size()), 1);
  auto cmp = std::memcmp(buf0.data(), buf1.data(), buf0.size());
  EXPECT_NE(cmp, 0);

  /* debug */
  // SPDLOG_INFO("buf0 = {}", absl::BytesToHexString(buf0));
  // SPDLOG_INFO("buf1 = {}", absl::BytesToHexString(buf1));
}

TEST(DrbgTest, BlockedRecvWork) {
  /* GIVEN */
  auto drbg0 = SyncDrbg();
  auto drbg1 = SyncDrbg();
  Buffer buf0(10);
  Buffer buf1(10);

  auto contexts = link::test::SetupWorld(2);

  /* WHEN */
  auto proc0 = std::async([&]() { drbg0.RecvState(contexts[0], 1); });

  // now drbg0 is in the syncing process
  sleep(1);  // wait for a second
  EXPECT_EQ(drbg0.Fill((char*)buf0.data(), buf0.size()), 0);

  auto proc1 = std::async([&]() { drbg1.SendState(contexts[1], 0); });
  proc0.get();
  proc1.get();

  /* THEN */
  drbg0.Fill((char*)buf0.data(), buf0.size());
  drbg1.Fill((char*)buf1.data(), buf1.size());
  auto cmp = std::memcmp(buf0.data(), buf1.data(), buf0.size());
  EXPECT_EQ(cmp, 0);

  /* debug */
  // SPDLOG_INFO("buf0 = {}", absl::BytesToHexString(buf0));
  // SPDLOG_INFO("buf1 = {}", absl::BytesToHexString(buf1));
}

TEST(DrbgTest, BlockedSendWork) {
  /* GIVEN */
  auto drbg0 = SyncDrbg();
  auto drbg1 = SyncDrbg();
  Buffer buf0(10);
  Buffer buf1(10);

  auto contexts = link::test::SetupWorld(2);

  /* WHEN */
  auto proc0 = std::async([&]() { drbg0.SendState(contexts[0], 1); });

  // now drbg0 is in the syncing process
  sleep(1);  // wait for a second
  EXPECT_EQ(drbg0.Fill((char*)buf0.data(), buf0.size()), 0);

  auto proc1 = std::async([&]() { drbg1.RecvState(contexts[1], 0); });
  proc0.get();
  proc1.get();

  /* THEN */
  drbg0.Fill((char*)buf0.data(), buf0.size());
  drbg1.Fill((char*)buf1.data(), buf1.size());
  auto cmp = std::memcmp(buf0.data(), buf1.data(), buf0.size());
  EXPECT_EQ(cmp, 0);

  /* debug */
  // SPDLOG_INFO("buf0 = {}", absl::BytesToHexString(buf0));
  // SPDLOG_INFO("buf1 = {}", absl::BytesToHexString(buf1));
}
}  // namespace yacl::crypto
