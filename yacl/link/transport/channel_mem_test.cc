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

#include "yacl/link/transport/channel_mem.h"

#include <chrono>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <future>
#include <memory>
#include <string>
#include <thread>

#include "fmt/format.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "yacl/base/byte_container_view.h"
#include "yacl/base/exception.h"

// disable detect leaks for brpc's "acceptable mem leak"
// https://github.com/apache/incubator-brpc/blob/0.9.6/src/brpc/server.cpp#L1138
extern "C" const char* __asan_default_options() { return "detect_leaks=0"; }

namespace yacl::link::transport::test {

class ChannelMemTest : public ::testing::Test {
 protected:
  void SetUp() override {
    size_t send_rank = 0;
    size_t recv_rank = 1;
    sender_ = std::make_shared<ChannelMem>(send_rank, recv_rank);
    receiver_ = std::make_shared<ChannelMem>(recv_rank, send_rank);
    sender_->SetPeer(receiver_);
    receiver_->SetPeer(sender_);
  }

  void TearDown() override {}

  std::shared_ptr<ChannelMem> sender_;
  std::shared_ptr<ChannelMem> receiver_;
};

TEST_F(ChannelMemTest, Normal) {
  const std::string key = "key";
  const std::string sent = "test";
  sender_->SendAsync(key, ByteContainerView{sent});
  auto received = receiver_->Recv(key);

  EXPECT_EQ(sent, std::string_view(received));

  auto wait = [](std::shared_ptr<ChannelMem>& l) {
    if (l) {
      l->WaitLinkTaskFinish();
    }
  };
  auto f_s = std::async(wait, std::ref(sender_));
  auto f_r = std::async(wait, std::ref(receiver_));
  f_s.get();
  f_r.get();
}

TEST_F(ChannelMemTest, WaitFinishSync) {
  const std::string key = "key";
  const std::string sent = "test";
  sender_->SendAsync(key, ByteContainerView{sent});
  auto received = receiver_->Recv(key);

  EXPECT_EQ(sent, std::string_view(received));

  auto f_s = std::async(
      [](std::shared_ptr<ChannelMem>& channel) {
        channel->WaitLinkTaskFinish();
      },
      std::ref(sender_));
  auto f_r = std::async(
      [](std::shared_ptr<ChannelMem>& channel) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        channel->WaitLinkTaskFinish();
      },
      std::ref(receiver_));
  f_s.get();
  f_r.get();
}

}  // namespace yacl::link::transport::test
