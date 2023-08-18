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

#include "yacl/link/factory.h"

#include <future>
#include <limits>

#include "fmt/format.h"
#include "gtest/gtest.h"

#include "yacl/link/context.h"
#include "yacl/link/link.h"

namespace yacl::link::test {

template <typename M>
class FactoryTest : public ::testing::Test {
 public:
  void SetUp() override {
    static int desc_count = 0;
    contexts_.resize(2);
    ContextDesc desc;
    desc.id = fmt::format("world_{}", desc_count++);
    desc.parties.push_back(ContextDesc::Party("alice", "127.0.0.1:63927"));
    desc.parties.push_back(ContextDesc::Party("bob", "127.0.0.1:63921"));

    auto create_brpc = [&](int self_rank) {
      contexts_[self_rank] = M().CreateContext(desc, self_rank);
    };

    std::vector<std::future<void>> creates;
    creates.push_back(std::async(create_brpc, 0));
    creates.push_back(std::async(create_brpc, 1));

    for (auto& f : creates) {
      f.get();
    }
  }

  void TearDown() override {
    auto wait = [&](int self_rank) {
      contexts_[self_rank]->WaitLinkTaskFinish();
    };

    std::vector<std::future<void>> waits;
    waits.push_back(std::async(wait, 0));
    waits.push_back(std::async(wait, 1));

    for (auto& f : waits) {
      f.get();
    }
  }

  std::vector<std::shared_ptr<Context>> contexts_;
};

using FactoryTestTypes = ::testing::Types<FactoryMem, FactoryBrpc>;
TYPED_TEST_SUITE(FactoryTest, FactoryTestTypes);

TYPED_TEST(FactoryTest, SendAsync) {
  auto test = [&](int self_rank) {
    int dst_rank = (self_rank + 1) % 2;
    this->contexts_[self_rank]->SendAsync(dst_rank, "test", "test");
    Buffer r = this->contexts_[self_rank]->Recv(dst_rank, "test");
    std::string r_str(r.data<const char>(), r.size());
    EXPECT_EQ(r_str, std::string("test"));
  };

  std::vector<std::future<void>> tests;
  tests.push_back(std::async(test, 0));
  tests.push_back(std::async(test, 1));

  for (auto& f : tests) {
    f.get();
  }
}

TYPED_TEST(FactoryTest, AllGather) {
  auto test = [&](int self_rank) {
    auto all =
        yacl::link::AllGather(this->contexts_[self_rank], "test", "test");
    for (Buffer& a : all) {
      EXPECT_EQ(std::string(a.data<const char>(), a.size()),
                std::string("test"));
    }
  };

  std::vector<std::future<void>> tests;
  tests.push_back(std::async(test, 0));
  tests.push_back(std::async(test, 1));

  for (auto& f : tests) {
    f.get();
  }
}

TYPED_TEST(FactoryTest, SendRecv) {
  auto test = [&](int self_rank) {
    if (self_rank == 0) {
      this->contexts_[0]->Send(1, "test", "test");
    } else {
      Buffer r = this->contexts_[1]->Recv(0, "test");
      EXPECT_EQ(std::string(r.data<const char>(), r.size()),
                std::string("test"));
    }
  };

  std::vector<std::future<void>> tests;
  tests.push_back(std::async(test, 0));
  tests.push_back(std::async(test, 1));

  for (auto& f : tests) {
    f.get();
  }
}

}  // namespace yacl::link::test
