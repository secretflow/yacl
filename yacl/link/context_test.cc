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

#include "yacl/link/context.h"

#include <future>
#include <limits>

#include "fmt/format.h"
#include "gmock/gmock.h"
#include "google/protobuf/util/json_util.h"
#include "gtest/gtest.h"

#include "yacl/base/byte_container_view.h"
#include "yacl/base/exception.h"
#include "yacl/link/factory.h"
#include "yacl/link/transport/channel_mem.h"

#include "yacl/link/link.pb.h"

namespace yacl::link::test {

class MockChannel : public transport::IChannel {
 public:
  MOCK_METHOD2(SendAsync,
               void(const std::string &key, ByteContainerView value));
  MOCK_METHOD2(SendAsync, void(const std::string &key, Buffer &&value));
  MOCK_METHOD2(SendAsyncThrottled,
               void(const std::string &key, ByteContainerView value));
  MOCK_METHOD2(SendAsyncThrottled,
               void(const std::string &key, Buffer &&value));
  MOCK_METHOD2(Send, void(const std::string &key, ByteContainerView value));
  MOCK_METHOD1(Recv, Buffer(const std::string &key));
  MOCK_METHOD2(OnMessage,
               void(const std::string &key, ByteContainerView value));
  MOCK_METHOD4(OnChunkedMessage,
               void(const std::string &key, ByteContainerView value,
                    size_t offset, size_t total_length));
  void SetRecvTimeout(uint64_t timeout_ms) override { timeout_ = timeout_ms; }
  uint64_t GetRecvTimeout() const override { return timeout_; }
  void WaitLinkTaskFinish() override {}
  void Abort() override {}
  void SetThrottleWindowSize(size_t) override {}
  void SetChunkParallelSendSize(size_t) override {}

  MOCK_METHOD1(TestSend, void(uint32_t));
  MOCK_METHOD0(TestRecv, void());

 private:
  std::uint64_t timeout_{std::numeric_limits<std::uint32_t>::max()};
};

class ContextConnectToMeshTest : public ::testing::Test {
 public:
  void SetUp() override {
    world_size_ = 3;
    self_rank_ = 1;
    channels_.resize(world_size_);
    channels_[0] = std::make_shared<MockChannel>();
    channels_[2] = std::make_shared<MockChannel>();
  }

  std::vector<std::shared_ptr<transport::IChannel>> channels_;
  size_t self_rank_;
  size_t world_size_;
};

TEST_F(ContextConnectToMeshTest, ConnectToMeshShouldOk) {
  // GIVEN
  auto msg_loop = std::make_shared<transport::ReceiverLoopMem>();
  ContextDesc ctx_desc;
  ctx_desc.connect_retry_interval_ms = 100;
  for (size_t rank = 0; rank < world_size_; rank++) {
    const auto id = fmt::format("id-{}", rank);
    const auto host = fmt::format("host-{}", rank);
    ctx_desc.parties.push_back({id, host});
  }
  Context ctx(ctx_desc, self_rank_, channels_, msg_loop);

  // THEN
  std::string event = fmt::format("connect_{}", self_rank_);
  for (size_t i = 0; i < world_size_; ++i) {
    if (i == self_rank_) {
      continue;
    }
    EXPECT_CALL(*std::static_pointer_cast<MockChannel>(channels_[i]),
                TestSend(testing::_));
    EXPECT_CALL(*std::static_pointer_cast<MockChannel>(channels_[i]),
                TestRecv());
  }
  // WHEN
  ctx.ConnectToMesh();
}

ACTION(ThrowNetworkErrorException) { throw ::yacl::NetworkError(); }

TEST_F(ContextConnectToMeshTest, ThrowExceptionIfNetworkError) {
  // GIVEN
  auto msg_loop = std::make_shared<transport::ReceiverLoopMem>();
  ContextDesc ctx_desc;
  ctx_desc.connect_retry_interval_ms = 100;
  for (size_t rank = 0; rank < world_size_; rank++) {
    const auto id = fmt::format("id-{}", rank);
    const auto host = fmt::format("host-{}", rank);
    ctx_desc.parties.push_back({id, host});
  }
  Context ctx(ctx_desc, self_rank_, channels_, msg_loop);

  std::string event = fmt::format("connect_{}", self_rank_);
  EXPECT_CALL(*std::static_pointer_cast<MockChannel>(channels_[0]),
              TestSend(testing::_))
      .WillRepeatedly(ThrowNetworkErrorException());

  // WHEN THEN
  EXPECT_THROW(ctx.ConnectToMesh(), ::yacl::RuntimeError);
}

TEST_F(ContextConnectToMeshTest, SetRecvTimeoutShouldOk) {
  // GIVEN
  auto msg_loop = std::make_shared<transport::ReceiverLoopMem>();
  ContextDesc ctx_desc;
  ctx_desc.recv_timeout_ms = 4800000000;
  for (size_t rank = 0; rank < world_size_; rank++) {
    const auto id = fmt::format("id-{}", rank);
    const auto host = fmt::format("host-{}", rank);
    ctx_desc.parties.push_back({id, host});
  }
  auto ctx =
      std::make_shared<Context>(ctx_desc, self_rank_, channels_, msg_loop);
  EXPECT_EQ(ctx->GetRecvTimeout(), 4800000000);
  // WHEN THEN
  {
    RecvTimeoutGuard guard(ctx, 2000);
    EXPECT_EQ(ctx->GetRecvTimeout(), 2000);
  }

  // THEN
  EXPECT_EQ(ctx->GetRecvTimeout(), 4800000000);
}

class ContextTest : public ::testing::Test {
 public:
  void SetUp() override {
    world_size_ = 3;

    ContextDesc ctx_desc;
    ctx_desc.recv_timeout_ms = 2000;  // 2 second
    for (size_t rank = 0; rank < world_size_; rank++) {
      const auto id = fmt::format("id-{}", rank);
      const auto host = fmt::format("host-{}", rank);
      ctx_desc.parties.push_back({id, host});
    }

    for (size_t rank = 0; rank < world_size_; rank++) {
      ctxs_.push_back(FactoryMem().CreateContext(ctx_desc, rank));
    }

    send_buffer_.resize(world_size_);
    receive_buffer.resize(world_size_);
    futures_.resize(world_size_);
    for (size_t sender = 0; sender < world_size_; ++sender) {
      send_buffer_[sender].resize(world_size_);
      receive_buffer[sender].resize(world_size_);
      futures_[sender].resize(world_size_);
    }
  }

  void join_all() {
    for (size_t i = 0; i < world_size_; ++i) {
      for (size_t j = 0; j < world_size_; ++j) {
        if (futures_[i][j].valid()) {
          futures_[i][j].get();
        }
      }
    }
  }

  std::vector<std::vector<std::string>> send_buffer_;
  std::vector<std::vector<std::string>> receive_buffer;
  std::vector<std::vector<std::future<void>>> futures_;
  std::vector<std::shared_ptr<Context>> ctxs_;
  size_t world_size_;
};

TEST_F(ContextTest, SendRecvShouldOk) {
  // GIVEN
  // build sent_values and received buffer
  for (size_t sender = 0; sender < world_size_; ++sender) {
    for (size_t receiver = 0; receiver < world_size_; ++receiver) {
      if (sender == receiver) {
        send_buffer_[sender][receiver] = "null";
        receive_buffer[sender][receiver] = "null";
        continue;
      }
      send_buffer_[sender][receiver] = fmt::format("{}->{}", sender, receiver);
    }
  }
  // WHEN
  auto recv_fn = [&](size_t receiver, size_t sender) {
    receive_buffer[sender][receiver] = ctxs_[receiver]->Recv(sender, "tag");
  };
  auto send_fn = [&](size_t sender, size_t receiver, const Buffer & /*value*/) {
    ctxs_[sender]->SendAsync(
        receiver, ByteContainerView(send_buffer_[sender][receiver]), "tag");
  };
  for (size_t sender = 0; sender < world_size_; ++sender) {
    for (size_t receiver = 0; receiver < world_size_; ++receiver) {
      if (sender == receiver) {
        continue;
      }
      futures_[sender][receiver] = std::async(recv_fn, receiver, sender);
    }
  }
  for (size_t sender = 0; sender < world_size_; ++sender) {
    for (size_t receiver = 0; receiver < world_size_; ++receiver) {
      if (sender == receiver) {
        continue;
      }
      auto _ = std::async(send_fn, sender, receiver,
                          yacl::Buffer(send_buffer_[sender][receiver]));
    }
  }
  join_all();

  // THEN
  EXPECT_EQ(send_buffer_, receive_buffer);
}

TEST_F(ContextTest, SubWorldShouldOk) {
  // GIVEN
  // original party ["id-1", "id-2"] will makeup new sub context
  std::vector<std::string> sub_parties({"id-1", "id-2"});

  // When
  std::vector<std::shared_ptr<Context>> sub_ctxs(2);
  std::string id_suffix = "id1,2";
  sub_ctxs[0] = ctxs_[1]->SubWorld(id_suffix, sub_parties);
  sub_ctxs[1] = ctxs_[2]->SubWorld(id_suffix, sub_parties);

  EXPECT_THROW(ctxs_[0]->SubWorld(id_suffix, sub_parties),
               ::yacl::RuntimeError);

  // Then
  EXPECT_EQ(sub_ctxs[0]->WorldSize(), 2);
  EXPECT_EQ(sub_ctxs[1]->WorldSize(), 2);

  EXPECT_EQ(sub_ctxs[0]->Rank(), 0);
  EXPECT_EQ(sub_ctxs[1]->Rank(), 1);

  // sub-world send & recv
  const std::string tag = "sub(0->1)";
  std::string value_send =
      "sub_world(rank 0 --> rank 1) ==> original_world(rank 1 --> rank 2)";
  Buffer send_buf(value_send.data(), static_cast<int64_t>(value_send.size()));
  sub_ctxs[0]->Send(1, send_buf, tag);

  auto value_recieve = sub_ctxs[1]->Recv(0, tag);

  EXPECT_EQ(send_buf, value_recieve);
}

TEST(EnvInfo, get_party_node_info) {
  setenv("config.node_id.host", "alice", 1);
  setenv("config.node_id.guest", "bob", 1);
  setenv("config.self_role", "guest", 1);

  std::vector<ContextDesc::Party> parties;
  size_t self_rank = -1;
  FactoryBrpcBlackBox().GetPartyNodeInfoFromEnv(parties, self_rank);

  EXPECT_EQ(self_rank, 0);
  EXPECT_EQ(parties.size(), 2);
}

TEST(ContextDesc, construct_from_pb) {
  ContextDescProto pb;
  std::string json = R"json(
  {
      "parties": [
          {
              "id": "alice",
              "host": "1.2.3.4:1000"
          },
          {
              "id": "bob",
              "host": "1.2.3.5:2000"
          }
      ],
      "connect_retry_times": 15,
      "recv_timeout_ms": 20000,
      "brpc_channel_protocol": "thrift",
      "brpc_channel_connection_type":"single",
      "enable_ssl": true,
      "client_ssl_opts": {
          "certificate_path": "certificate_path/alice",
          "private_key_path": "private_key_path/alice",
          "verify_depth": 1,
          "ca_file_path": "ca_file_path/alice"
      },
      "server_ssl_opts": {
          "certificate_path": "certificate_path/bob",
          "private_key_path": "private_key_path/bob",
          "verify_depth": 1,
          "ca_file_path": "ca_file_path/bob"
      }
  })json";

  EXPECT_TRUE(google::protobuf::util::JsonStringToMessage(json, &pb).ok());

  ContextDesc desc(pb);

  EXPECT_EQ(desc.id, ContextDesc::kDefaultId);
  EXPECT_EQ(desc.parties.size(), 2);
  EXPECT_EQ(desc.parties[0].id, "alice");
  EXPECT_EQ(desc.parties[1].host, "1.2.3.5:2000");
  EXPECT_EQ(desc.connect_retry_times, 15);
  EXPECT_EQ(desc.connect_retry_interval_ms,
            ContextDesc::kDefaultConnectRetryIntervalMs);
  EXPECT_EQ(desc.recv_timeout_ms, 20000);
  EXPECT_EQ(desc.http_max_payload_size,
            ContextDesc::kDefaultHttpMaxPayloadSize);
  EXPECT_EQ(desc.http_timeout_ms, ContextDesc::kDefaultHttpTimeoutMs);
  EXPECT_EQ(desc.throttle_window_size, ContextDesc::kDefaultThrottleWindowSize);
  EXPECT_EQ(desc.brpc_channel_protocol, "thrift");
  EXPECT_EQ(desc.brpc_channel_connection_type, "single");
  EXPECT_EQ(desc.enable_ssl, true);
  EXPECT_EQ(desc.client_ssl_opts.cert.certificate_path,
            "certificate_path/alice");
  EXPECT_EQ(desc.client_ssl_opts.cert.private_key_path,
            "private_key_path/alice");
  EXPECT_EQ(desc.server_ssl_opts.verify.verify_depth, 1);
  EXPECT_EQ(desc.server_ssl_opts.verify.ca_file_path, "ca_file_path/bob");
  EXPECT_EQ(desc.exit_if_async_error, true);
  EXPECT_EQ(desc.link_type, ContextDesc::kDefaultLinkType);
}

}  // namespace yacl::link::test
