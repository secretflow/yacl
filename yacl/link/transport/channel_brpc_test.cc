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
#include <filesystem>
#include <future>
#include <string>
#include <thread>

#include "fmt/format.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "yacl/base/byte_container_view.h"
#include "yacl/base/exception.h"

#include "interconnection/link/transport.pb.h"

// disable detect leaks for brpc's "acceptable mem leak"
// https://github.com/apache/incubator-brpc/blob/0.9.6/src/brpc/server.cpp#L1138
extern "C" const char* __asan_default_options() { return "detect_leaks=0"; }

namespace yacl::link::transport::test {

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
    auto options = ChannelBrpc::GetDefaultOptions();
    sender_ = std::make_shared<ChannelBrpc>(send_rank, recv_rank, options);
    receiver_ = std::make_shared<ChannelBrpc>(recv_rank, send_rank, options);

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

TEST_P(ChannelBrpcWithLimitTest, Async) {
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

  EXPECT_LT(span, 100 * 1000);

  f_r.get();
}

TEST_P(ChannelBrpcWithLimitTest, AsyncWithThrottleLimit) {
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
    sender_->SendAsyncThrottled(key, ByteContainerView{sended_data[i]});
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
    sender_->SendAsyncThrottled(key, ByteContainerView{sended_data[i]});
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

class ChannelBrpcSSLTest : public ::testing::Test {
 protected:
  void SetUp() override {
    // ca
    YACL_ENFORCE(system("openssl genrsa -out ca.key 2048") == 0);
    YACL_ENFORCE(system("openssl req -new -x509 -key ca.key -out ca.crt -subj "
                        "\"/CN=sf\"") == 0);

    YACL_ENFORCE(std::filesystem::create_directory("./test_0"));
    YACL_ENFORCE(std::filesystem::create_directory("./test_1"));

    // rank 0 server
    GenerateCert("./test_0", "server", "./ca.crt", "./ca.key");
    // rank 0 client
    GenerateCert("./test_0", "client", "./ca.crt", "./ca.key");
    // rank 1 server
    GenerateCert("./test_1", "server", "./ca.crt", "./ca.key");
    // rank 1 client
    GenerateCert("./test_1", "client", "./ca.crt", "./ca.key");
  }

  void TearDown() override {
    (void)!system("rm -rf ./test_0");
    (void)!system("rm -rf ./test_1");
  }

  void GenerateCert(const std::string& dir, const std::string& name,
                    const std::string& ca_crt_path,
                    const std::string ca_key_path) {
    std::string key_cmd =
        fmt::format("openssl genrsa -out {}/{}.key 2048", dir, name);
    std::string csr_cmd = fmt::format(
        "openssl req -new -key {}/{}.key -out {}/{}.csr -subj "
        "\"/CN=sf_test\"",
        dir, name, dir, name);
    std::string crt_cmd = fmt::format(
        "openssl x509 -req -in {}/{}.csr -CA {} -CAkey {} "
        "-CAcreateserial -out {}/{}.crt",
        dir, name, ca_crt_path, ca_key_path, dir, name);

    YACL_ENFORCE(system(key_cmd.c_str()) == 0);
    YACL_ENFORCE(system(csr_cmd.c_str()) == 0);
    YACL_ENFORCE(system(crt_cmd.c_str()) == 0);
  }

  void WaitChannelEnd(const std::shared_ptr<ChannelBrpc>& receiver,
                      const std::shared_ptr<ChannelBrpc>& sender) {
    auto wait = [](const std::shared_ptr<ChannelBrpc>& l) {
      if (l) {
        l->WaitLinkTaskFinish();
      }
    };
    auto f_s = std::async(wait, sender);
    auto f_r = std::async(wait, receiver);
    f_s.get();
    f_r.get();
  }

 protected:
  ChannelBrpc::Options channel_options_ = ChannelBrpc::GetDefaultOptions();
};

TEST_F(ChannelBrpcSSLTest, OneWaySSL) {
  std::srand(std::time(nullptr));
  const size_t send_rank = 0;
  const size_t recv_rank = 1;

  auto sender =
      std::make_shared<ChannelBrpc>(send_rank, recv_rank, channel_options_);
  auto receiver =
      std::make_shared<ChannelBrpc>(recv_rank, send_rank, channel_options_);

  // let sender rank as 0, receiver rank as 1.
  // receiver listen messages from sender(rank 0).
  auto receiver_loop = std::make_unique<ReceiverLoopBrpc>();
  receiver_loop->AddListener(0, receiver);
  SSLOptions receiver_ssl_opts;
  receiver_ssl_opts.cert.certificate_path = "./test_1/server.crt";
  receiver_ssl_opts.cert.private_key_path = "./test_1/server.key";
  std::string receiver_host =
      receiver_loop->Start("127.0.0.1:0", &receiver_ssl_opts);

  auto sender_loop = std::make_unique<ReceiverLoopBrpc>();
  sender_loop->AddListener(1, sender);
  SSLOptions sender_ssl_opts;
  sender_ssl_opts.cert.certificate_path = "./test_0/server.crt";
  sender_ssl_opts.cert.private_key_path = "./test_0/server.key";
  std::string sender_host = sender_loop->Start("127.0.0.1:0", &sender_ssl_opts);

  // client ssl opts (no certificate, only verify)
  SSLOptions client_ssl_opts;
  client_ssl_opts.verify.verify_depth = 1;
  client_ssl_opts.verify.ca_file_path = "./ca.crt";
  sender->SetPeerHost(receiver_host, &client_ssl_opts);
  receiver->SetPeerHost(sender_host, &client_ssl_opts);

  const std::string key = "key";
  const std::string sent = RandStr(100U);
  sender->SendAsync(key, ByteContainerView{sent});
  auto received = receiver->Recv(key);

  EXPECT_EQ(sent, std::string_view(received));

  WaitChannelEnd(receiver, sender);
}

TEST_F(ChannelBrpcSSLTest, TwoWaySSL) {
  std::srand(std::time(nullptr));
  const size_t send_rank = 0;
  const size_t recv_rank = 1;

  auto sender =
      std::make_shared<ChannelBrpc>(send_rank, recv_rank, channel_options_);
  auto receiver =
      std::make_shared<ChannelBrpc>(recv_rank, send_rank, channel_options_);

  // let sender rank as 0, receiver rank as 1.
  // receiver listen messages from sender(rank 0).
  auto receiver_loop = std::make_unique<ReceiverLoopBrpc>();
  receiver_loop->AddListener(0, receiver);
  SSLOptions receiver_ssl_opts;
  receiver_ssl_opts.cert.certificate_path = "./test_1/server.crt";
  receiver_ssl_opts.cert.private_key_path = "./test_1/server.key";
  receiver_ssl_opts.verify.verify_depth = 1;
  receiver_ssl_opts.verify.ca_file_path = "./ca.crt";
  std::string receiver_host =
      receiver_loop->Start("127.0.0.1:0", &receiver_ssl_opts);

  auto sender_loop = std::make_unique<ReceiverLoopBrpc>();
  sender_loop->AddListener(1, sender);
  SSLOptions sender_ssl_opts;
  sender_ssl_opts.cert.certificate_path = "./test_0/server.crt";
  sender_ssl_opts.cert.private_key_path = "./test_0/server.key";
  sender_ssl_opts.verify.verify_depth = 1;
  sender_ssl_opts.verify.ca_file_path = "./ca.crt";
  std::string sender_host = sender_loop->Start("127.0.0.1:0", &sender_ssl_opts);

  SSLOptions s_client_ssl_opts;
  s_client_ssl_opts.cert.certificate_path = "./test_0/client.crt";
  s_client_ssl_opts.cert.private_key_path = "./test_0/client.key";
  s_client_ssl_opts.verify.verify_depth = 1;
  s_client_ssl_opts.verify.ca_file_path = "./ca.crt";
  sender->SetPeerHost(receiver_host, &s_client_ssl_opts);

  SSLOptions r_client_ssl_opts;
  r_client_ssl_opts.cert.certificate_path = "./test_1/client.crt";
  r_client_ssl_opts.cert.private_key_path = "./test_1/client.key";
  r_client_ssl_opts.verify.verify_depth = 1;
  r_client_ssl_opts.verify.ca_file_path = "./ca.crt";
  receiver->SetPeerHost(sender_host, &r_client_ssl_opts);

  const std::string key = "key";
  const std::string sent = RandStr(100U);
  sender->SendAsync(key, ByteContainerView{sent});
  auto received = receiver->Recv(key);

  EXPECT_EQ(sent, std::string_view(received));

  WaitChannelEnd(receiver, sender);
}

using namespace yacl::link;
namespace ic_pb = org::interconnection::link;
namespace ic = org::interconnection;

class DelayReceiverServiceImpl : public ic_pb::ReceiverService {
 public:
  DelayReceiverServiceImpl() = default;

  void Push(::google::protobuf::RpcController* /*cntl_base*/,
            const ic_pb::PushRequest* request, ic_pb::PushResponse* response,
            ::google::protobuf::Closure* done) override {
    brpc::ClosureGuard done_guard(done);
    std::this_thread::sleep_for(std::chrono::milliseconds(2000));
    response->mutable_header()->set_error_code(ic::ErrorCode::OK);
    response->mutable_header()->set_error_msg("");
  }
};

class DummyReceiverLoopBrpc final : public IReceiverLoop {
 public:
  ~DummyReceiverLoopBrpc() override { Stop(); }

  virtual void AddListener(size_t rank, std::shared_ptr<ChannelBase> listener) {
    auto ret = listeners_.emplace(rank, std::move(listener));
    if (!ret.second) {
      YACL_THROW_LOGIC_ERROR("duplicated listener for rank={}", rank);
    }
  }

  void Stop() override {
    server_.Stop(0);
    server_.Join();
  }

  std::string Start(const std::string& host) {
    if (server_.IsRunning()) {
      YACL_THROW_LOGIC_ERROR("brpc server is already running");
    }

    auto svc = std::make_unique<DelayReceiverServiceImpl>();
    if (server_.AddService(svc.get(), brpc::SERVER_OWNS_SERVICE) == 0) {
      static_cast<void>(svc.release());
    } else {
      YACL_THROW_IO_ERROR("brpc server failed to add msg service");
    }

    brpc::ServerOptions options;
    if (server_.Start(host.data(), &options) != 0) {
      YACL_THROW_IO_ERROR("brpc server failed start");
    }

    return butil::endpoint2str(server_.listen_address()).c_str();
  }

 protected:
  std::map<size_t, std::shared_ptr<ChannelBase>> listeners_;
  brpc::Server server_;
};

}  // namespace yacl::link::transport::test
