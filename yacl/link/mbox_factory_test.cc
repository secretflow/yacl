// Copyright 2025 Ant Group Co., Ltd.
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

#include "yacl/link/mbox_factory.h"

#include <gtest/gtest.h>

#include <thread>
#include <vector>

namespace yacl::link {

TEST(InMemoryMbox, BasicSendRecv) {
  auto mboxs = CreateInMemoryMboxs(2);

  // Send from rank 0 to rank 1
  std::vector<uint8_t> data = {1, 2, 3, 4, 5};
  mboxs[0]->Send(1, "test_key", data);

  // Receive on rank 1
  auto received = mboxs[1]->Recv(0, "test_key", 1000);

  ASSERT_TRUE(received.has_value());
  EXPECT_EQ(*received, data);
}

TEST(InMemoryMbox, SendRecvMultiple) {
  auto mboxs = CreateInMemoryMboxs(3);

  // Send messages between different ranks
  std::vector<uint8_t> data1 = {1, 2, 3};
  std::vector<uint8_t> data2 = {4, 5, 6};
  std::vector<uint8_t> data3 = {7, 8, 9};

  mboxs[0]->Send(1, "msg1", data1);
  mboxs[1]->Send(2, "msg2", data2);
  mboxs[2]->Send(0, "msg3", data3);

  // Receive in different order
  auto received3 = mboxs[0]->Recv(2, "msg3", 1000);
  auto received1 = mboxs[1]->Recv(0, "msg1", 1000);
  auto received2 = mboxs[2]->Recv(1, "msg2", 1000);

  ASSERT_TRUE(received1.has_value());
  ASSERT_TRUE(received2.has_value());
  ASSERT_TRUE(received3.has_value());

  EXPECT_EQ(*received1, data1);
  EXPECT_EQ(*received2, data2);
  EXPECT_EQ(*received3, data3);
}

TEST(InMemoryMbox, TimeoutTest) {
  auto mboxs = CreateInMemoryMboxs(2);

  // Try to receive non-existent message with timeout
  auto received = mboxs[0]->Recv(1, "nonexistent", 100);

  EXPECT_FALSE(received.has_value());
}

TEST(InMemoryMbox, ConcurrentSendRecv) {
  auto mboxs = CreateInMemoryMboxs(2);

  std::vector<uint8_t> data = {10, 20, 30, 40, 50};

  // Start receiving in a separate thread
  std::thread receiver([&]() {
    auto received = mboxs[1]->Recv(0, "concurrent", 5000);
    ASSERT_TRUE(received.has_value());
    EXPECT_EQ(*received, data);
  });

  // Send after a small delay
  std::this_thread::sleep_for(std::chrono::milliseconds(10));
  mboxs[0]->Send(1, "concurrent", data);

  receiver.join();
}

}  // namespace yacl::link