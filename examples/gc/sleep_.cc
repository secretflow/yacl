#include <unistd.h>

#include <future>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <string>
#include <type_traits>
#include <variant>
#include <vector>

#include "fmt/format.h"
// #include "gtest/gtest.h"
#include "yacl/link/context.h"
#include "yacl/link/factory.h"
#include "yacl/link/link.h"

class FactoryTest {
 public:
  FactoryTest() {
    static int desc_count = 0;
    contexts_.resize(2);
    yacl::link::ContextDesc desc;
    desc.id = fmt::format("world_{}", desc_count++);
    desc.brpc_retry_count = 20;
    desc.parties.push_back(
        yacl::link::ContextDesc::Party("alice", "172.18.0.2:63927"));
    desc.parties.push_back(
        yacl::link::ContextDesc::Party("bob", "172.18.0.3:63921"));
    auto create_brpc = [&](int self_rank) {
      contexts_[self_rank] =
          yacl::link::FactoryBrpc().CreateContext(desc, self_rank);
    };
    std::vector<std::future<void>> creates;
    creates.push_back(std::async(create_brpc, 0));
    for (auto& f : creates) {
      f.get();
    }
    std::cout << "Connect to Bob successfully\n";
  }

  void work() {
    auto test = [&](int self_rank) {
      int dst_rank = 1 - self_rank;
      this->contexts_[self_rank]->SendAsync(dst_rank, "Hello I am 0", "test");
      yacl::Buffer r = this->contexts_[self_rank]->Recv(dst_rank, "test");
      std::string r_str(r.data<const char>(), r.size());
      std::cout << self_rank << " Receive " << r_str << '\n';
    };
    std::vector<std::future<void>> tests;
    tests.push_back(std::async(test, 0));
    for (auto& f : tests) {
      f.get();
    }
  }

  ~FactoryTest() {
    auto wait = [&](int self_rank) {
      contexts_[self_rank]->WaitLinkTaskFinish();
    };
    std::vector<std::future<void>> waits;
    waits.push_back(std::async(wait, 0));
    for (auto& f : waits) {
      f.get();
    }
  }
  std::vector<std::shared_ptr<yacl::link::Context>> contexts_;
};

int main() {
  FactoryTest F;
  sleep(2);
  F.work();
  return 0;
}