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

#include "yacl/link/transport/channel.h"

#include <gflags/gflags.h>
#include <spdlog/spdlog.h>

#include "fmt/format.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "brpc/errno.pb.h"
#include "interconnection/link/transport.pb.h"

namespace brpc {

DECLARE_bool(usercode_in_pthread);

}  // namespace brpc

namespace yacl::link::transport::test {

struct Initial {
  Initial() { brpc::FLAGS_usercode_in_pthread = true; }
};

static Initial g_initial{};

namespace ic_pb = org::interconnection::link;

class MockTransportLink : public TransportLink {
 public:
  using TransportLink::TransportLink;
  MOCK_METHOD(void, SetMaxBytesPerChunk, (size_t), (override));

  MOCK_METHOD(void, UnpackMonoRequest,
              (const Request&, std::string*, ByteContainerView*),
              (const, override));
  MOCK_METHOD(void, UnpackChunckRequest,
              (const Request& request, std::string*, ByteContainerView*,
               size_t*, size_t*),
              (const, override));
  MOCK_METHOD(void, FillResponseOk, (const Request&, Response*),
              (const, override));
  MOCK_METHOD(void, FillResponseError, (const Request&, Response*),
              (const, override));
  MOCK_METHOD(bool, IsChunkedRequest, (const Request&), (const, override));
  MOCK_METHOD(bool, IsMonoRequest, (const Request&), (const, override));
  MOCK_METHOD(void, SendRequest, (const Request&, uint32_t), (const, override));

  // provided an implementation in order to test SendChunked
  size_t GetMaxBytesPerChunk() const override {
    static size_t max_bytes_per_chunk = 2;
    return max_bytes_per_chunk;
  }
  std::unique_ptr<::google::protobuf::Message> PackMonoRequest(
      const std::string& key, ByteContainerView value) const override {
    auto request = std::make_unique<ic_pb::PushRequest>();
    request->set_key(key);
    request->set_value(value.data(), value.size());
    request->set_trans_type(ic_pb::TransType::MONO);

    return request;
  }
  std::unique_ptr<::google::protobuf::Message> PackChunkedRequest(
      const std::string& key, ByteContainerView value, size_t offset,
      size_t total_length) const override {
    auto request = std::make_unique<ic_pb::PushRequest>();
    {
      request->set_sender_rank(self_rank_);
      request->set_key(key);
      request->set_value(value.data(), value.size());
      request->set_trans_type(ic_pb::TransType::CHUNKED);
      request->mutable_chunk_info()->set_chunk_offset(offset);
      request->mutable_chunk_info()->set_message_length(total_length);
    }
    return request;
  }
};

class ChannelSendRetryTest : public testing::Test {
 protected:
  void SetUp() override {
    brpc::FLAGS_usercode_in_pthread = true;
    SPDLOG_INFO("brpc::usercode_in_pthread: {}",
                brpc::FLAGS_usercode_in_pthread);

    const size_t send_rank = 0;
    const size_t recv_rank = 1;
    sender_delegate_ =
        std::make_shared<MockTransportLink>(send_rank, recv_rank);
    RetryOptions retry_options;
    retry_options.aggressive_retry = false;
    // reset time intervals to accelerate
    retry_options.retry_interval_ms = 10;
    retry_options.retry_interval_incr_ms = 20;
    retry_options.max_retry_interval_ms = 100;
    retry_options.error_codes = {brpc::ENOSERVICE, brpc::ENOMETHOD};
    retry_options.http_codes = {brpc::HTTP_STATUS_BAD_GATEWAY,
                                brpc::HTTP_STATUS_MULTIPLE_CHOICES};

    sender_ = std::make_shared<Channel>(sender_delegate_, false, retry_options);
    SPDLOG_INFO("test_start");
  }

  void TearDown() override {
    sender_delegate_.reset();
    sender_.reset();
  }

  std::shared_ptr<MockTransportLink> sender_delegate_;
  std::shared_ptr<Channel> sender_;
};

TEST_F(ChannelSendRetryTest, NoRetrySuccess) {
  EXPECT_CALL(*sender_delegate_, SendRequest)
      .Times(1)
      .WillRepeatedly([](const TransportLink::Request&, uint32_t) {});
  const std::string key = "key";
  auto request = sender_delegate_->PackMonoRequest(key, "t");
  sender_->SendRequestWithRetry(*request, 0);
}

TEST_F(ChannelSendRetryTest, RetrySuccess) {
  EXPECT_CALL(*sender_delegate_, SendRequest)
      .Times(2)
      .WillOnce(testing::Throw(yacl::LinkError(
          "valid error code, will retry once and success.", brpc::ENOSERVICE)))
      .WillRepeatedly([](const TransportLink::Request&, uint32_t) {});
  const std::string key = "key";
  auto request = sender_delegate_->PackMonoRequest(key, "t");
  sender_->SendRequestWithRetry(*request, 0);
}

TEST_F(ChannelSendRetryTest, RetryFail) {
  EXPECT_CALL(*sender_delegate_, SendRequest)
      .Times(4)
      .WillRepeatedly(testing::Throw(
          yacl::LinkError("valid error code, will retry max count and fail.",
                          brpc::ENOSERVICE)));
  const std::string key = "key";
  auto request = sender_delegate_->PackMonoRequest(key, "t");
  EXPECT_THROW(sender_->SendRequestWithRetry(*request, 0), yacl::LinkError);
}

TEST_F(ChannelSendRetryTest, HttpNoRetryFail) {
  EXPECT_CALL(*sender_delegate_, SendRequest)
      .Times(1)
      .WillRepeatedly(testing::Throw(
          yacl::LinkError("not valid http code and no retry.", brpc::EHTTP,
                          brpc::HTTP_STATUS_GATEWAY_TIMEOUT)));
  const std::string key = "key";
  auto request = sender_delegate_->PackMonoRequest(key, "t");
  EXPECT_THROW(sender_->SendRequestWithRetry(*request, 0), yacl::LinkError);
}

TEST_F(ChannelSendRetryTest, HttpRetrySuccess) {
  EXPECT_CALL(*sender_delegate_, SendRequest)
      .Times(2)
      .WillOnce(testing::Throw(
          yacl::LinkError("valid http code, will retry once and success.",
                          brpc::EHTTP, brpc::HTTP_STATUS_BAD_GATEWAY)))
      .WillRepeatedly([](const TransportLink::Request&, uint32_t) {});
  const std::string key = "key";
  auto request = sender_delegate_->PackMonoRequest(key, "t");
  sender_->SendRequestWithRetry(*request, 0);
}

TEST_F(ChannelSendRetryTest, HttpRetryFail) {
  EXPECT_CALL(*sender_delegate_, SendRequest)
      .Times(4)
      .WillRepeatedly(testing::Throw(
          yacl::LinkError("valid http code, will retry max count and fail.",
                          brpc::EHTTP, brpc::HTTP_STATUS_BAD_GATEWAY)));
  const std::string key = "key";
  auto request = sender_delegate_->PackMonoRequest(key, "t");
  EXPECT_THROW(sender_->SendRequestWithRetry(*request, 0), yacl::LinkError);
}

}  // namespace yacl::link::transport::test
