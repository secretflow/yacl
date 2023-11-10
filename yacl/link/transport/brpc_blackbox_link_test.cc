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

#include "yacl/link/transport/brpc_blackbox_link.h"

#include <chrono>
#include <cstddef>
#include <future>
#include <string>
#include <thread>

#include "absl/strings/str_split.h"
#include "fmt/format.h"
#include "gtest/gtest.h"
#include "spdlog/spdlog.h"

#include "yacl/base/byte_container_view.h"
#include "yacl/base/exception.h"
#include "yacl/link/transport/blackbox_interconnect/blackbox_service_errorcode.h"
#include "yacl/link/transport/channel.h"

#include "interconnection/link/transport.pb.h"
#include "yacl/link/transport/blackbox_interconnect/blackbox_dummy_service.pb.h"
#include "yacl/link/transport/blackbox_interconnect/blackbox_service.pb.h"

// disable detect leaks for brpc's "acceptable mem leak"
// https://github.com/apache/incubator-brpc/blob/0.9.6/src/brpc/server.cpp#L1138
extern "C" const char* __asan_default_options() { return "detect_leaks=0"; }

#define DEBUG_LOG SPDLOG_DEBUG
namespace blackbox_interconnect {
class DummyBlackBoxServiceImpl : public DummyBlackBoxService {
 public:
  void default_method(google::protobuf::RpcController* cntl_base,
                      const HttpRequest* /*request*/,
                      HttpResponse* /*response*/,
                      google::protobuf::Closure* done) override {
    brpc::ClosureGuard done_guard(done);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    auto* cntl = static_cast<brpc::Controller*>(cntl_base);
    std::vector<absl::string_view> paths =
        absl::StrSplit(cntl->http_request().unresolved_path(), '/');
    const auto* topic = cntl->http_request().GetHeader("x-ptp-topic");
    TransportOutbound response;

    response.set_code(error_code::Code("OK"));
    if (topic == nullptr) {
      response.set_code(error_code::Code("BadRequest"));
      response.set_message("topic is null");
    } else if (!paths.empty()) {
      DEBUG_LOG("service topic: {}", *topic);
      auto cmd = paths.back();
      DEBUG_LOG("service cmd: {}", cmd);
      if (cmd == "invoke" || cmd == "push") {
        msg_db_[*topic].push(cntl->request_attachment().to_string());
      } else if (cmd == "pop") {
        if (!msg_db_[*topic].empty()) {
          response.set_payload(msg_db_[*topic].front());
          msg_db_[*topic].pop();
        }
      } else {
        response.set_code(error_code::Code("UnsupportedUriPath"));
      }
    }

    cntl->response_attachment().append(response.SerializeAsString());
  }

 private:
  std::map<std::string, std::queue<std::string>> msg_db_;
};

}  // namespace blackbox_interconnect
namespace yacl::link::transport::test {

namespace ic_pb = org::interconnection::link;
namespace ic = org::interconnection;
namespace bb_ic = blackbox_interconnect;

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

class BlackBoxLinkTest : public ::testing::Test {
 protected:
  void SetUp() override {
    std::srand(std::time(nullptr));
    const size_t send_rank = 0;
    const size_t recv_rank = 1;

    auto options = BrpcBlackBoxLink::GetDefaultOptions();
    auto sender_delegate =
        std::make_shared<BrpcBlackBoxLink>(send_rank, recv_rank, options);
    auto receiver_delegate =
        std::make_shared<BrpcBlackBoxLink>(recv_rank, send_rank, options);
    sender_ = std::make_shared<Channel>(sender_delegate, false, RetryOptions());
    receiver_ =
        std::make_shared<Channel>(receiver_delegate, false, RetryOptions());

    std::string server_addr = "127.0.0.1:0";

    if (mock_service_) {
      if (server_.IsRunning()) {
        server_.Stop(0);
        server_.Join();
      }
      auto service = std::make_unique<bb_ic::DummyBlackBoxServiceImpl>();
      if (server_.AddService(service.get(), brpc::SERVER_OWNS_SERVICE,
                             "/v1/* => default_method") == 0) {
        // Once add service succeed, give up ownership
        static_cast<void>(service.release());
      } else {
        YACL_THROW_IO_ERROR("brpc server failed to add msg service");
      }
      brpc::ServerOptions options;
      if (server_.Start(server_addr.c_str(), &options) != 0) {
        YACL_THROW_IO_ERROR("brpc server failed start");
      }

      server_addr = butil::endpoint2str(server_.listen_address()).c_str();
    }

    setenv("system.transport", server_addr.c_str(), 1);
    setenv("config.trace_id", "1234", 1);
    setenv("config.token", "1234", 1);
    setenv("config.session_id", "1234", 1);
    setenv(("config.inst_id." + party_id[send_rank]).c_str(),
           node_id[send_rank].c_str(), 1);
    setenv(("config.inst_id." + party_id[recv_rank]).c_str(),
           node_id[recv_rank].c_str(), 1);
    //
    sender_delegate->SetPeerHost(party_id[send_rank], node_id[send_rank],
                                 party_id[recv_rank], node_id[recv_rank],
                                 nullptr);
    receiver_delegate->SetPeerHost(party_id[recv_rank], node_id[recv_rank],
                                   party_id[send_rank], node_id[send_rank],
                                   nullptr);

    receive_loop_ = std::make_unique<ReceiverLoopBlackBox>();
    receive_loop_->AddLinkAndChannel(send_rank, sender_, sender_delegate);
    receive_loop_->AddLinkAndChannel(recv_rank, receiver_, receiver_delegate);

    receive_loop_->Start();
  }

  void TearDown() override {
    auto wait = [](std::shared_ptr<Channel>& l) {
      if (l) {
        l->WaitLinkTaskFinish();
      }
    };

    auto f_s = std::async(wait, std::ref(sender_));
    auto f_r = std::async(wait, std::ref(receiver_));
    f_s.get();
    f_r.get();
    // stop receive thread before stop server
    receive_loop_->Stop();
    sender_.reset();
    receiver_.reset();
    // stop serving
    if (server_.IsRunning()) {
      server_.Stop(0);
      server_.Join();
    }
  }
  brpc::Server server_;
  bool mock_service_ = true;
  std::shared_ptr<Channel> sender_;
  std::shared_ptr<Channel> receiver_;
  std::unique_ptr<ReceiverLoopBlackBox> receive_loop_;
  inline static std::vector<std::string> party_id = {"alice", "bob"};
  inline static std::vector<std::string> node_id = {"1234", "5678"};
};

// FIXME: This test fails on Linux CI
TEST_F(BlackBoxLinkTest, DISABLED_Normal_Empty) {
  const std::string key = "key";
  const std::string sent;
  sender_->SendAsync(key, ByteContainerView{sent});
  DEBUG_LOG("Send end...");
  auto received = receiver_->Recv(key);
  DEBUG_LOG("Recv end...");

  EXPECT_EQ(sent, std::string_view(received));
}

// FIXME: This test fails on Linux CI
TEST_F(BlackBoxLinkTest, DISABLED_Timeout) {
  receiver_->SetRecvTimeout(50U);
  const std::string key = "key";
  std::string received;
  EXPECT_THROW(receiver_->Recv(key), IoError);
}

// FIXME: This test fails on Linux CI
TEST_F(BlackBoxLinkTest, DISABLED_Sync_Normal_Len100) {
  const std::string key = "key";
  const std::string sent = RandStr(100U);
  sender_->Send(key, ByteContainerView{sent});
  auto received = receiver_->Recv(key);

  EXPECT_EQ(sent, std::string_view(received));
}

// FIXME: This test fails on Linux CI
TEST_F(BlackBoxLinkTest, DISABLED_Async_Normal_Len100) {
  const std::string key = "key";
  const std::string sent = RandStr(100U);
  sender_->SendAsync(key, ByteContainerView{sent});
  auto received = receiver_->Recv(key);

  EXPECT_EQ(sent, std::string_view(received));
}

// FIXME: This test fails on Linux CI
TEST_F(BlackBoxLinkTest, DISABLED_Largedata_1000000) {
  const std::string key = "key";
  const std::string sent = RandStr(1000000U);
  sender_->SendAsync(key, ByteContainerView{sent});
  std::this_thread::sleep_for(std::chrono::milliseconds(1000));
  auto received = receiver_->Recv(key);

  EXPECT_EQ(sent, std::string_view(received));
}

}  // namespace yacl::link::transport::test
