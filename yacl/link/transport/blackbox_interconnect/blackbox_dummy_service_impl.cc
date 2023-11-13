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

#include "yacl/link/transport/blackbox_interconnect/blackbox_dummy_service_impl.h"

#include <chrono>
#include <cstdint>
#include <memory>
#include <thread>

#include "absl/strings/str_split.h"
#include "fmt/format.h"
#include "spdlog/spdlog.h"

#include "yacl/base/exception.h"
#include "yacl/link/transport/blackbox_interconnect/blackbox_service_errorcode.h"

// disable detect leaks for brpc's "acceptable mem leak"
// https://github.com/apache/incubator-brpc/blob/0.9.6/src/brpc/server.cpp#L1138
extern "C" const char* __asan_default_options() { return "detect_leaks=0"; }

namespace bb_ic = blackbox_interconnect;

namespace yacl::link::transport::blackbox_interconnect {

DummyBlackBoxServiceImpl::DummyBlackBoxServiceImpl(
    std::map<std::string, std::string> node_id_to_ip,
    brpc::ChannelOptions options)
    : node_id_to_ip_(std::move(node_id_to_ip)), options_(std::move(options)) {
  const char* load_balancer = "";
  for (auto& [node_id, url] : node_id_to_ip_) {
    auto brpc_channel = std::make_unique<brpc::Channel>();

    int res = brpc_channel->Init(url.c_str(), load_balancer, &options_);
    if (res != 0) {
      YACL_THROW("Fail to init transport service, node={}, url={}, err_code={}",
                 node_id, url, res);
    }
    node_channels_[node_id] = std::move(brpc_channel);
    SPDLOG_INFO("Service Route: {} -> {}", node_id, url);
  }
}

void DummyBlackBoxServiceImpl::OnInvoke(const std::string* topic,
                                        std::string request) {
  SPDLOG_INFO("invoke: topic {}", *topic);
  std::lock_guard<std::mutex> guard(msg_mtx_);
  recv_msgs_[*topic].push(std::move(request));
  msg_cond_.notify_all();
}

bool DummyBlackBoxServiceImpl::OnPush(brpc::Controller* cntl,
                                      bb_ic::TransportOutbound& response) {
  const auto* target_node =
      cntl->http_request().GetHeader("x-ptp-target-node-id");
  if (target_node == nullptr) {
    response.set_code(bb_ic::error_code::Code("BadRequest"));
    response.set_message("Header: x-ptp-target-node-id is null");
  } else if (node_channels_.find(*target_node) == node_channels_.end()) {
    response.set_code(bb_ic::error_code::Code("BadRequest"));
    response.set_message(fmt::format(
        "Header: x-ptp-target-node-id: {} is not configed", *target_node));
  } else {
    auto old_cntl = std::make_unique<brpc::Controller>();
    old_cntl->http_request().Swap(cntl->http_request());
    old_cntl->request_attachment().swap(cntl->request_attachment());

    bool success = false;
    for (uint32_t i = 0; i != invoke_max_retry_cnt_; ++i) {
      auto new_cntl = std::make_unique<brpc::Controller>();
      new_cntl->http_request().Swap(old_cntl->http_request());
      new_cntl->ignore_eovercrowded();
      new_cntl->http_request().set_method(brpc::HTTP_METHOD_POST);
      new_cntl->http_request().uri() =
          node_id_to_ip_[*target_node] + "/v1/interconn/chan/invoke";
      new_cntl->request_attachment().swap(old_cntl->request_attachment());
      SPDLOG_DEBUG("push: target_node {}, retry: {}",
                   new_cntl->request_attachment().to_string(), i);
      node_channels_[*target_node]->CallMethod(nullptr, new_cntl.get(), nullptr,
                                               nullptr, nullptr);
      if (new_cntl->Failed()) {
        SPDLOG_INFO(
            "Rpc failed, error_code: {}, error_info: {}, uri: "
            "{}:{}/v1/interconn/chan/invoke",
            new_cntl->ErrorCode(), new_cntl->ErrorText(), *target_node,
            node_id_to_ip_[*target_node]);
        new_cntl.swap(old_cntl);
        std::this_thread::sleep_for(
            std::chrono::milliseconds(invoke_retry_interval_ms_));
      } else {
        success = true;
        cntl->response_attachment().swap(new_cntl->response_attachment());
        break;
      }
    }

    if (success) {
      return true;
    }

    SPDLOG_ERROR("Rpc failed, uri: {}: {}/v1/interconn/chan/invoke",
                 *target_node, node_id_to_ip_[*target_node]);
    response.set_code(bb_ic::error_code::Code("NetworkError"));
    response.set_message(fmt::format("invoke to {}: {} failed.", *target_node,
                                     node_id_to_ip_[*target_node]));
  }
  return false;
}

void DummyBlackBoxServiceImpl::OnPop(brpc::Controller* cntl,
                                     bb_ic::TransportOutbound& response,
                                     const std::string* topic) {
  unsigned long timeout = 0;
  auto timeout_str = cntl->http_request().uri().GetQuery("timeout");
  if (timeout_str != nullptr) {
    timeout = std::stoul(*timeout_str);
  }
  std::unique_lock<std::mutex> lock(msg_mtx_);
  msg_cond_.wait_for(lock, std::chrono::seconds(timeout),
                     [&] { return !recv_msgs_[*topic].empty(); });
  if (!recv_msgs_[*topic].empty()) {
    response.set_payload(recv_msgs_[*topic].front());
    recv_msgs_[*topic].pop();
  } else {
    // return OK when timeout, but payload is empty.
    response.set_code(bb_ic::error_code::Code("OK"));
  }
}

void DummyBlackBoxServiceImpl::default_method(
    google::protobuf::RpcController* cntl_base,
    const bb_ic::HttpRequest* /*request*/, bb_ic::HttpResponse* /*response*/,
    google::protobuf::Closure* done) {
  brpc::ClosureGuard done_guard(done);
  auto* cntl = static_cast<brpc::Controller*>(cntl_base);
  std::vector<absl::string_view> paths =
      absl::StrSplit(cntl->http_request().unresolved_path(), '/');
  const auto* topic = cntl->http_request().GetHeader("x-ptp-topic");

  bb_ic::TransportOutbound response;
  response.set_code(bb_ic::error_code::Code("OK"));

  if (topic == nullptr) {
    response.set_code(bb_ic::error_code::Code("BadRequest"));
    response.set_message("topic is null");
  } else if (!paths.empty()) {
    auto cmd = paths.back();
    SPDLOG_DEBUG("cmd: {}", cmd);

    if (cmd == "invoke") {
      OnInvoke(topic, cntl->request_attachment().to_string());
    } else if (cmd == "push") {
      auto succeed = OnPush(cntl, response);
      if (succeed) {
        return;
      }
    } else if (cmd == "pop") {
      OnPop(cntl, response, topic);
    } else {
      response.set_code(bb_ic::error_code::Code("UnsupportedUriPath"));
    }
  }

  cntl->response_attachment().append(response.SerializeAsString());
}

}  // namespace yacl::link::transport::blackbox_interconnect
