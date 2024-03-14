// Copyright 2023 Ant Group Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "yacl/link/transport/brpc_blackbox_link.h"

#include <chrono>
#include <cstddef>
#include <exception>
#include <memory>
#include <optional>
#include <thread>
#include <utility>

#include "absl/strings/str_replace.h"
#include "spdlog/spdlog.h"

#include "yacl/base/exception.h"
#include "yacl/link/transport/blackbox_interconnect/blackbox_service_errorcode.h"
#include "yacl/link/transport/channel.h"

#include "yacl/link/transport/blackbox_interconnect/blackbox_service.pb.h"
namespace yacl::link::transport {

namespace bb_ic = blackbox_interconnect;

namespace ic = org::interconnection;
namespace ic_pb = org::interconnection::link;

namespace {

const auto* const kTransportAddrKey = "system.transport";
const auto* const kTraceIdKey = "config.trace_id";
const auto* const kTokenKey = "config.token";
const auto* const kSessionIdKey = "config.session_id";
const auto* const kInstIdKeyPrefix = "config.inst_id.";

const auto* const kHttpHeadProviderCode = "x-ptp-tecn-provider-code";
const auto* const kHttpHeadTraceId = "x-ptp-trace-id";
const auto* const kHttpHeadToken = "x-ptp-token";
const auto* const kHttpHeadTargetNodeId = "x-ptp-target-node-id";
const auto* const kHttpHeadSourceNodeId = "x-ptp-source-node-id";

const auto* const kHttpHeadSrcInstId = "x-ptp-source-inst-id";
const auto* const kHttpHeadInstId = "x-ptp-target-inst-id";
const auto* const kHttpHeadSessionId = "x-ptp-session-id";
const auto* const kHttpHeadTopic = "x-ptp-topic";
const auto* const kHttpHeadHost = "host";

}  // namespace

ReceiverLoopBlackBox::~ReceiverLoopBlackBox() { Stop(); }

void ReceiverLoopBlackBox::Stop() {
  for (auto& [_, delegate] : links_) {
    delegate->StopReceive();
  }
  for (auto& channel_thread : threads_) {
    if (channel_thread.joinable()) {
      channel_thread.join();
    }
  }
}

void ReceiverLoopBlackBox::Start() {
  for (auto& [rank, channel] : listeners_) {
    YACL_ENFORCE(links_.find(rank) != links_.end(), "{} is not in delegates",
                 rank);
    auto link = links_[rank];
    threads_.emplace_back(
        [](std::shared_ptr<Channel> chn,
           std::shared_ptr<BrpcBlackBoxLink> link) {
          link->StartReceive();
          while (link->CanReceive()) {
            auto request = link->TryReceive();
            if (request) {
              ic_pb::PushResponse response;
              chn->OnRequest(*request, &response);
              if (response.mutable_header()->error_code() !=
                  ic::ErrorCode::OK) {
                SPDLOG_ERROR("OnRequest failed, error_code: {}, error_info: {}",
                             response.mutable_header()->error_code(),
                             response.mutable_header()->error_msg());
              }
            }
          }
        },
        channel, link);
  }
}

void BrpcBlackBoxLink::StartReceive() { is_recv_.store(true); }

bool BrpcBlackBoxLink::CanReceive() { return is_recv_.load(); }

void BrpcBlackBoxLink::StopReceive() { is_recv_.store(false); }

std::optional<ic_pb::PushRequest> BrpcBlackBoxLink::TryReceive() {
  bb_ic::TransportOutbound response;
  std::optional<ic_pb::PushRequest> ret;
  brpc::Controller cntl;
  SetHttpHeader(&cntl, recv_topic_);
  auto uri_str =
      host_ + kUrlPrefix + "pop?timeout=" + std::to_string(pop_timeout_s_);
  cntl.set_timeout_ms(1000LL * (pop_timeout_s_ + 1));
  cntl.http_request().uri() = uri_str;
  channel_->CallMethod(nullptr, &cntl, nullptr, nullptr, nullptr);

  if (cntl.Failed()) {
    SPDLOG_ERROR("Rpc failed, error_code: {}, error_info: {}, uri: {}",
                 cntl.ErrorCode(), cntl.ErrorText(), uri_str);
  } else {
    if (!response.ParseFromString(cntl.response_attachment().to_string())) {
      SPDLOG_ERROR("{} failed, error_code: {}({}), error_info: {}", uri_str,
                   response.code(), bb_ic::error_code::Desc(response.code()),
                   response.message());
      return ret;
    }

    if (response.code() == bb_ic::error_code::Code("ResourceNotFound") ||
        response.payload().empty()) {
      SPDLOG_INFO("We will wait for topic: {}", recv_topic_);
    } else if (response.code() != bb_ic::error_code::Code("OK")) {
      SPDLOG_ERROR("{} failed, error_code: {}({}), error_info: {}", uri_str,
                   response.code(), bb_ic::error_code::Desc(response.code()),
                   response.message());
    } else {
      ic_pb::PushRequest request;

      if (!request.ParseFromString(response.payload())) {
        SPDLOG_ERROR("response payload cannot be parsed.");
      } else {
        ret = std::move(request);
      }
    }
  }

  return ret;
}

brpc::ChannelOptions BrpcBlackBoxLink::GetChannelOption(
    const SSLOptions* ssl_opts) {
  brpc::ChannelOptions options;
  {
    if (options_.channel_protocol != "http" &&
        options_.channel_protocol != "h2") {
      YACL_THROW_LOGIC_ERROR(
          "channel protocol {} is not valid for blackbox channel",
          options_.channel_protocol);
    }
    options.protocol = options_.channel_protocol;
    options.connection_type = options_.channel_connection_type;
    options.connect_timeout_ms = 20000;
    options.timeout_ms = options_.http_timeout_ms;
    options.max_retry = 0;
    if (ssl_opts != nullptr) {
      options.mutable_ssl_options()->client_cert.certificate =
          ssl_opts->cert.certificate_path;
      options.mutable_ssl_options()->client_cert.private_key =
          ssl_opts->cert.private_key_path;
      options.mutable_ssl_options()->verify.verify_depth =
          ssl_opts->verify.verify_depth;
      options.mutable_ssl_options()->verify.ca_file_path =
          ssl_opts->verify.ca_file_path;
    }
  }
  return options;
}

void BrpcBlackBoxLink::SetPeerHost(const std::string& self_id,
                                   const std::string& self_node_id,
                                   const std::string& peer_id,
                                   const std::string& peer_node_id,
                                   const SSLOptions* ssl_opts) {
  auto* host = std::getenv(kTransportAddrKey);
  YACL_ENFORCE(host != nullptr, "environment variable {} is not found",
               kTransportAddrKey);
  host_ = host;
  host_ = absl::StrReplaceAll(host_, {{"http://", ""}, {"https://", ""}});
  SPDLOG_INFO("Get transport service address: {}", host_);

  auto options = GetChannelOption(ssl_opts);
  const char* load_balancer = "";
  auto brpc_channel = std::make_unique<brpc::Channel>();

  int res = brpc_channel->Init(host_.c_str(), load_balancer, &options);
  if (res != 0) {
    YACL_THROW_NETWORK_ERROR(
        "Fail to connect to transport service, host={}, err_code={}", host_,
        res);
  }

  auto local_inst_key = kInstIdKeyPrefix + self_id;
  auto* local_inst = std::getenv(local_inst_key.c_str());
  YACL_ENFORCE(local_inst != nullptr, "environment variable {} is not found",
               local_inst_key);

  auto peer_inst_key = kInstIdKeyPrefix + peer_id;
  auto* peer_inst = std::getenv(peer_inst_key.c_str());
  YACL_ENFORCE(peer_inst != nullptr, "environment variable {} is not found",
               peer_inst_key);

  auto* trace_id = std::getenv(kTraceIdKey);
  YACL_ENFORCE(trace_id != nullptr, "environment variable {} is not found",
               kTraceIdKey);
  auto* token = std::getenv(kTokenKey);
  YACL_ENFORCE(token != nullptr, "environment variable {} is not found",
               kTokenKey);
  auto* session_id = std::getenv(kSessionIdKey);
  YACL_ENFORCE(session_id != nullptr, "environment variable {} is not found",
               kSessionIdKey);

  channel_ = std::move(brpc_channel);
  send_topic_ = self_id + '-' + peer_id;
  recv_topic_ = peer_id + '-' + self_id;
  peer_host_ = peer_id;

  http_headers_[kHttpHeadProviderCode] = "SecretFlow";
  http_headers_[kHttpHeadTraceId] = trace_id;
  http_headers_[kHttpHeadToken] = token;
  http_headers_[kHttpHeadTargetNodeId] = peer_node_id;
  http_headers_[kHttpHeadSourceNodeId] = self_node_id;
  http_headers_[kHttpHeadSessionId] = session_id;
  http_headers_[kHttpHeadHost] = host_;
  http_headers_[kHttpHeadInstId] = peer_inst;
  http_headers_[kHttpHeadSrcInstId] = local_inst;
}

void BrpcBlackBoxLink::SetHttpHeader(brpc::Controller* controller,
                                     const std::string& topic) const {
  for (auto& [k, v] : http_headers_) {
    controller->http_request().SetHeader(k, v);
  }
  controller->http_request().SetHeader(kHttpHeadTopic, topic);
  controller->http_request().set_method(brpc::HTTP_METHOD_POST);
}

void BrpcBlackBoxLink::SendRequest(const Request& request,
                                   uint32_t timeout_ms) const {
  bb_ic::TransportOutbound response;
  auto request_str = request.SerializeAsString();
  int pushs = 0;
  do {
    ++pushs;

    brpc::Controller cntl;
    cntl.ignore_eovercrowded();
    if (timeout_ms != 0) {
      cntl.set_timeout_ms(timeout_ms);
    }
    cntl.http_request().uri() = host_ + kUrlPrefix + "push";
    SetHttpHeader(&cntl, send_topic_);
    cntl.request_attachment().append(request_str);

    channel_->CallMethod(nullptr, &cntl, nullptr, nullptr, nullptr);
    if (cntl.Failed()) {
      ThrowLinkErrorByBrpcCntl(cntl);
    }

    YACL_ENFORCE(
        response.ParseFromString(cntl.response_attachment().to_string()),
        "Parse message failed.");

    if (response.code() == bb_ic::error_code::Code("OK")) {
      return;
    }

    if (response.code() != bb_ic::error_code::Code("QueueFull")) {
      ThrowLinkErrorByBrpcCntl(cntl);
    } else {
      SPDLOG_WARN(
          "{} push error due to transport service queue is full, try "
          "again...",
          pushs);
      bthread_usleep(push_wait_ms_ * 1000);
    }

  } while (response.code() == bb_ic::error_code::Code("QueueFull"));
}

}  // namespace yacl::link::transport
