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
#include <memory>
#include <string>

#include "absl/strings/str_replace.h"
#include "absl/strings/str_split.h"
#include "brpc/channel.h"
#include "brpc/server.h"

#include "yacl/base/exception.h"
#include "yacl/link/transport/blackbox_interconnect/blackbox_dummy_service_impl.h"

extern char** environ;

namespace yacl::link::transport::blackbox_interconnect {

class MockTransport {
 public:
  static std::map<std::string, std::string> GetNodeID2NodeIPFromEnv() {
    auto* self_role = std::getenv("config.self_role");
    YACL_ENFORCE(self_role != nullptr,
                 "config.self_role is not configed in env.");

    static constexpr std::string_view kNodeInfoPrefix = "config.node_id.";
    static constexpr std::string_view kNodeIPInfoPrefix = "config.node_ip.";
    std::map<std::string, std::string> id_to_node_id;
    std::map<std::string, std::string> id_to_node_ip;
    for (char** env = environ; *env != nullptr; ++env) {
      std::vector<std::string> k_v = absl::StrSplit(*env, '=');
      if ((!absl::StartsWith(k_v[0], kNodeInfoPrefix)) &&
          (!absl::StartsWith(k_v[0], kNodeIPInfoPrefix))) {
        continue;
      }
      YACL_ENFORCE(k_v.size() == 2, "{} format error: should be A=B",
                   std::string(*env));

      auto party_id = absl::StrReplaceAll(
          k_v[0], {{kNodeInfoPrefix, ""}, {kNodeIPInfoPrefix, ""}});

      if (party_id == self_role) {
        continue;
      }

      if (absl::StartsWith(k_v[0], kNodeIPInfoPrefix)) {
        id_to_node_ip[party_id] = k_v[1];
      } else {
        id_to_node_id[party_id] = k_v[1];
      }
    }

    YACL_ENFORCE(id_to_node_id.size() == id_to_node_ip.size(),
                 "The number of {}({}) is not equal to {}({}).",
                 kNodeInfoPrefix, id_to_node_id.size(), kNodeIPInfoPrefix,
                 id_to_node_ip.size());

    std::map<std::string, std::string> node_id_to_node_ip;
    for (auto id_iter = id_to_node_id.begin(), ip_iter = id_to_node_ip.begin();
         id_iter != id_to_node_id.end(); ++id_iter, ++ip_iter) {
      YACL_ENFORCE(id_iter->first == ip_iter->first,
                   "id not match in config: {} - {}", id_iter->first,
                   ip_iter->first);
      node_id_to_node_ip[id_iter->second] = ip_iter->second;
    }
    return node_id_to_node_ip;
  }

  static std::string GetLocalUrlFromEnv() {
    auto* local_ip = std::getenv("system.transport");
    YACL_ENFORCE(local_ip != nullptr,
                 "system.transport is not configed in env.");
    return local_ip;
  }

  void StartFromEnv(const brpc::ChannelOptions& options) {
    auto local_url = GetLocalUrlFromEnv();
    auto node_id_to_node_ip = GetNodeID2NodeIPFromEnv();
    Start(local_url, node_id_to_node_ip, options);
  }

  void Start(const std::string& local_transport_url,
             const std::map<std::string, std::string>& node_id_to_ip,
             const brpc::ChannelOptions& options) {
    auto service =
        std::make_unique<DummyBlackBoxServiceImpl>(node_id_to_ip, options);
    if (server_.AddService(service.get(), brpc::SERVER_OWNS_SERVICE,
                           "/v1/interconn/chan/* => default_method") == 0) {
      // Once add service succeed, give up ownership
      static_cast<void>(service.release());
    } else {
      YACL_THROW_IO_ERROR("brpc server failed to add msg service");
    }
    brpc::ServerOptions server_opt;
    server_opt.has_builtin_services = false;
    if (server_.Start(local_transport_url.c_str(), &server_opt) != 0) {
      YACL_THROW_IO_ERROR("brpc server failed start at {}",
                          local_transport_url);
    }
  }

  void Stop() {
    if (server_.IsRunning()) {
      server_.Stop(0);
    }
  }

  ~MockTransport() { Stop(); }

 private:
  brpc::Server server_;
};

}  // namespace yacl::link::transport::blackbox_interconnect
