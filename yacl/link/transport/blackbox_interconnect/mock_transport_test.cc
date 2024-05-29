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

#include "yacl/link/transport/blackbox_interconnect/mock_transport.h"

#include <memory>

#include "gtest/gtest.h"
#include "spdlog/spdlog.h"

#include "yacl/link/transport/blackbox_interconnect/blackbox_service.pb.h"

namespace bb_ic = blackbox_interconnect;
namespace yacl::link::transport::blackbox_interconnect {

class MockTransportTest : public ::testing::Test {
 public:
  void SetUp() override {
    brpc::ChannelOptions options;
    {
      options.protocol = "http";
      options.connection_type = "";
      options.connect_timeout_ms = 20000;
      options.timeout_ms = 1e4;
      options.max_retry = 3;
    }
    transport_.Start(server_url_, {{peer_, server_url_}}, options);

    auto brpc_channel = std::make_unique<brpc::Channel>();

    int res = brpc_channel->Init(server_url_.c_str(), "", &options);
    if (res != 0) {
      YACL_THROW_NETWORK_ERROR(
          "Fail to connect to transport service, host={}, err_code={}",
          server_url_, res);
    }
    channel_ = std::move(brpc_channel);
  }

  void TearDown() override { transport_.Stop(); }

 public:
  std::string peer_{"peer"};
  std::string server_url_{"127.0.0.1:61234"};
  std::shared_ptr<brpc::Channel> channel_;
  MockTransport transport_;
};

TEST_F(MockTransportTest, base_test) {
  std::string msg = "yacl_blackbox";
  std::string topic = "test_topic";

  {
    brpc::Controller cntl;
    cntl.http_request().uri() = server_url_ + "/v1/interconn/chan/push";
    cntl.http_request().set_method(brpc::HTTP_METHOD_POST);
    cntl.http_request().SetHeader("x-ptp-topic", topic);
    cntl.http_request().SetHeader("x-ptp-target-node-id", peer_);
    cntl.request_attachment() = msg;
    channel_->CallMethod(nullptr, &cntl, nullptr, nullptr, nullptr);
    EXPECT_FALSE(cntl.Failed());

    bb_ic::TransportOutbound response;
    response.ParseFromString(cntl.response_attachment().to_string());
    SPDLOG_INFO("response: code: {}, msg: {}", response.code(),
                response.message());
    EXPECT_EQ(response.code(), "E0000000000");
  }
  {
    brpc::Controller cntl;
    cntl.http_request().uri() = server_url_ + "/v1/interconn/chan/pop";
    cntl.http_request().set_method(brpc::HTTP_METHOD_POST);
    cntl.http_request().SetHeader("x-ptp-topic", topic);

    channel_->CallMethod(nullptr, &cntl, nullptr, nullptr, nullptr);
    EXPECT_FALSE(cntl.Failed());

    ::blackbox_interconnect::TransportOutbound response;
    response.ParseFromString(cntl.response_attachment().to_string());
    SPDLOG_INFO("response: code: {}, msg: {}", response.code(),
                response.message());
    EXPECT_EQ(msg, response.payload());
  }
}

TEST(UtilTest, get_local_url) {
  std::string url = "127.0.0.1:61234";
  setenv("system.transport", url.c_str(), 1);

  auto res = MockTransport::GetLocalUrlFromEnv();

  EXPECT_EQ(res, url);
}

TEST(UtilTest, get_node_ip_map) {
  setenv("config.self_role", "bbb", 1);
  setenv("config.node_id.aaa", "node_aaa", 1);
  setenv("config.node_id.bbb", "node_bbb", 1);
  setenv("config.node_ip.aaa", "node_ip_aaa", 1);
  setenv("config.node_ip.bbb", "node_ip_bbb", 1);

  auto res = MockTransport::GetNodeID2NodeIPFromEnv();

  EXPECT_EQ(res.size(), 1);
  EXPECT_EQ(res.begin()->first, "node_aaa");
  EXPECT_EQ(res.begin()->second, "node_ip_aaa");
}

}  // namespace yacl::link::transport::blackbox_interconnect
