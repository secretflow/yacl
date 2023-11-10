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

#pragma once

#include <algorithm>
#include <condition_variable>
#include <map>
#include <memory>
#include <mutex>
#include <queue>
#include <string>

#include "brpc/channel.h"

#include "yacl/link/transport/blackbox_interconnect/blackbox_service_errorcode.h"

#include "yacl/link/transport/blackbox_interconnect/blackbox_dummy_service.pb.h"
#include "yacl/link/transport/blackbox_interconnect/blackbox_service.pb.h"

namespace yacl::link::transport::blackbox_interconnect {

class DummyBlackBoxServiceImpl
    : public ::blackbox_interconnect::DummyBlackBoxService {
 public:
  DummyBlackBoxServiceImpl(std::map<std::string, std::string> node_id_to_ip,
                           brpc::ChannelOptions options);

  void default_method(google::protobuf::RpcController* cntl_base,
                      const ::blackbox_interconnect::HttpRequest* /*request*/,
                      ::blackbox_interconnect::HttpResponse* /*response*/,
                      google::protobuf::Closure* done) override;

  void OnInvoke(const std::string* topic, std::string request);

  bool OnPush(brpc::Controller* cntl,
              ::blackbox_interconnect::TransportOutbound& response);

  void OnPop(brpc::Controller* cntl,
             ::blackbox_interconnect::TransportOutbound& response,
             const std::string* topic);

 private:
  std::map<std::string, std::string> node_id_to_ip_;
  brpc::ChannelOptions options_;
  std::map<std::string, std::shared_ptr<brpc::Channel>> node_channels_;
  std::string peer_url_;
  std::mutex msg_mtx_;
  std::condition_variable msg_cond_;
  std::map<std::string, std::queue<std::string>> recv_msgs_;
  uint32_t invoke_max_retry_cnt_ = 10;
  uint32_t invoke_retry_interval_ms_ = 1000;
};

}  // namespace yacl::link::transport::blackbox_interconnect
