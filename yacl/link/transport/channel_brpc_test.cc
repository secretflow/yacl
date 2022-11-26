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

#include "yacl/link/transport/channel_brpc.h"

#include <chrono>
#include <cstdlib>
#include <ctime>
#include <future>
#include <string>

#include "fmt/format.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "yacl/base/byte_container_view.h"
#include "yacl/base/exception.h"

// disable detect leaks for brpc's "acceptable mem leak"
// https://github.com/apache/incubator-brpc/blob/0.9.6/src/brpc/server.cpp#L1138
extern "C" const char* __asan_default_options() { return "detect_leaks=0"; }

namespace yacl::link::test {

static std::string RandStr(size_t length) {
  auto randchar = []() -> char {
    const char charset[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";
    const size_t max_index = (sizeof(charset) - 1);
    return charset[rand() % max_index];
  };
  std::string str(length, 0);
  std::generate_n(str.begin(), length, randchar);
  return str;
}

class ChannelBrpcTest : public ::testing::Test {
 protected:
  void SetUp() override {
    std::srand(std::time(nullptr));
    const size_t send_rank = 0;
    const size_t recv_rank = 1;

    sender_ = std::make_shared<ChannelBrpc>(send_rank, recv_rank, options_);
    receiver_ = std::make_shared<ChannelBrpc>(recv_rank, send_rank, options_);

    // let sender rank as 0, receiver rank as 1.
    // receiver_ listen messages from sender(rank 0).
    receiver_loop_ = std::make_unique<ReceiverLoopBrpc>();
    receiver_loop_->AddListener(0, receiver_);
    receiver_host_ = receiver_loop_->Start("127.0.0.1:0");

    sender_loop_ = std::make_unique<ReceiverLoopBrpc>();
    sender_loop_->AddListener(1, sender_);
    sender_host_ = sender_loop_->Start("127.0.0.1:0");

    //
    sender_->SetPeerHost(receiver_host_);
    receiver_->SetPeerHost(sender_host_);
  }

  void TearDown() override {
    auto wait = [](std::shared_ptr<ChannelBrpc>& l) {
      if (l) {
        l->WaitLinkTaskFinish();
      }
    };
    auto f_s = std::async(wait, std::ref(sender_));
    auto f_r = std::async(wait, std::ref(receiver_));
    f_s.get();
    f_r.get();
  }

  ChannelBrpc::Options options_;
  std::shared_ptr<ChannelBrpc> sender_;
  std::shared_ptr<ChannelBrpc> receiver_;
  std::string receiver_host_;
  std::unique_ptr<ReceiverLoopBrpc> receiver_loop_;
  std::string sender_host_;
  std::unique_ptr<ReceiverLoopBrpc> sender_loop_;
};

TEST_F(ChannelBrpcTest, Normal_Empty) {
  const std::string key = "key";
  const std::string sent;
  sender_->SendAsync(key, ByteContainerView{sent});
  auto received = receiver_->Recv(key);

  EXPECT_EQ(sent, std::string_view(received));
}

TEST_F(ChannelBrpcTest, Timeout) {
  receiver_->SetRecvTimeout(500U);
  const std::string key = "key";
  std::string received;
  EXPECT_THROW(receiver_->Recv(key), IoError);
}

TEST_F(ChannelBrpcTest, Normal_Len100) {
  const std::string key = "key";
  const std::string sent = RandStr(100U);
  sender_->SendAsync(key, ByteContainerView{sent});
  auto received = receiver_->Recv(key);

  EXPECT_EQ(sent, std::string_view(received));
}

class ChannelBrpcWithLimitTest
    : public ChannelBrpcTest,
      public ::testing::WithParamInterface<std::tuple<size_t, size_t>> {};

TEST_P(ChannelBrpcWithLimitTest, SendAsync) {
  const size_t size_limit_per_call = std::get<0>(GetParam());
  const size_t size_to_send = std::get<1>(GetParam());

  sender_->SetHttpMaxPayloadSize(size_limit_per_call);

  const std::string key = "key";
  const std::string sent = RandStr(size_to_send);
  sender_->SendAsync(key, ByteContainerView{sent});
  auto received = receiver_->Recv(key);

  EXPECT_EQ(sent, std::string_view(received));
}

TEST_P(ChannelBrpcWithLimitTest, Wait) {
  const size_t size_limit_per_call = std::get<0>(GetParam());
  const size_t size_to_send = std::get<1>(GetParam());

  sender_->SetHttpMaxPayloadSize(size_limit_per_call);

  const size_t test_size = 128 + (std::rand() % 128);

  std::vector<std::string> sended_data(test_size);

  for (size_t i = 0; i < test_size; i++) {
    const std::string key = fmt::format("Key_{}", i);
    sended_data[i] = RandStr(size_to_send);
    sender_->SendAsync(key, ByteContainerView{sended_data[i]});
  }

  sender_->WaitAsyncSendToFinish();

  for (size_t i = 0; i < test_size; i++) {
    const std::string key = fmt::format("Key_{}", i);
    auto received = receiver_->Recv(key);
    EXPECT_EQ(sended_data[i], std::string_view(received));
  }
}

TEST_P(ChannelBrpcWithLimitTest, Unread) {
  const size_t size_limit_per_call = std::get<0>(GetParam());
  const size_t size_to_send = std::get<1>(GetParam());

  sender_->SetHttpMaxPayloadSize(size_limit_per_call);

  const size_t test_size = 128 + (std::rand() % 128);

  std::vector<std::string> sended_data(test_size);

  for (size_t i = 0; i < test_size; i++) {
    const std::string key = fmt::format("Key_{}", i);
    sended_data[i] = RandStr(size_to_send);
    sender_->SendAsync(key, ByteContainerView{sended_data[i]});
  }
}

TEST_P(ChannelBrpcWithLimitTest, ThrottleWindow) {
  const size_t size_limit_per_call = std::get<0>(GetParam());
  const size_t size_to_send = std::get<1>(GetParam());
  sender_->SetThrottleWindowSize(size_to_send);
  sender_->SetHttpMaxPayloadSize(size_limit_per_call);
  const size_t test_size = 128 + (std::rand() % 128);
  std::vector<std::string> sended_data(test_size);

  auto read = [&] {
    for (size_t i = 0; i < test_size; i++) {
      const std::string key = fmt::format("Key_{}", i);
      if (i == 0) {
        usleep(100 * 1000);
      }
      auto received = receiver_->Recv(key);
      EXPECT_EQ(sended_data[i], std::string_view(received));
    }
  };
  auto f_r = std::async(read);

  auto start = std::chrono::steady_clock::now();
  for (size_t i = 0; i < test_size; i++) {
    const std::string key = fmt::format("Key_{}", i);
    sended_data[i] = RandStr(size_to_send);
    sender_->SendAsync(key, ByteContainerView{sended_data[i]});
  }
  auto end = std::chrono::steady_clock::now();

  double span =
      std::chrono::duration_cast<std::chrono::microseconds>(end - start)
          .count();
  if (size_to_send < test_size) {
    EXPECT_GT(span, 100 * 1000);
  } else {
    EXPECT_LT(span, 100 * 1000);
  }

  f_r.get();
}

TEST_P(ChannelBrpcWithLimitTest, ThrottleWindowUnread) {
  const size_t size_limit_per_call = std::get<0>(GetParam());
  const size_t size_to_send = std::get<1>(GetParam());
  sender_->SetThrottleWindowSize(size_to_send);
  sender_->SetHttpMaxPayloadSize(size_limit_per_call);
  const size_t test_size = 128 + (std::rand() % 128);
  std::vector<std::string> sended_data(test_size);

  auto read = [&] {
    for (size_t i = 0; i < 18; i++) {
      const std::string key = fmt::format("Key_{}", i);
      if (i == 0) {
        usleep(100 * 1000);
      }
      auto received = receiver_->Recv(key);
      EXPECT_EQ(sended_data[i], std::string_view(received));
    }
    receiver_->WaitLinkTaskFinish();
  };
  auto f_r = std::async(read);

  auto start = std::chrono::steady_clock::now();
  for (size_t i = 0; i < test_size; i++) {
    const std::string key = fmt::format("Key_{}", i);
    sended_data[i] = RandStr(size_to_send);
    sender_->SendAsync(key, ByteContainerView{sended_data[i]});
  }
  auto end = std::chrono::steady_clock::now();

  double span =
      std::chrono::duration_cast<std::chrono::microseconds>(end - start)
          .count();
  if (size_to_send < test_size) {
    EXPECT_GT(span, 100 * 1000);
  } else {
    EXPECT_LT(span, 100 * 1000);
  }
  sender_->WaitLinkTaskFinish();
  f_r.get();
  sender_.reset();
  receiver_.reset();
}

TEST_P(ChannelBrpcWithLimitTest, Send) {
  const size_t size_limit_per_call = std::get<0>(GetParam());
  const size_t size_to_send = std::get<1>(GetParam());

  sender_->SetHttpMaxPayloadSize(size_limit_per_call);

  const std::string key = "key";
  const std::string sent = RandStr(size_to_send);
  sender_->Send(key, sent);
  auto received = receiver_->Recv(key);

  EXPECT_EQ(sent, std::string_view(received));
}

INSTANTIATE_TEST_SUITE_P(
    Normal_Instances, ChannelBrpcWithLimitTest,
    testing::Combine(testing::Values(9, 17),
                     testing::Values(1, 2, 9, 10, 11, 20, 19, 21, 1001)),
    [](const testing::TestParamInfo<ChannelBrpcWithLimitTest::ParamType>&
           info) {
      std::string name = fmt::format("Limit_{}_Len_{}", std::get<0>(info.param),
                                     std::get<1>(info.param));
      return name;
    });

}  // namespace yacl::link::test
