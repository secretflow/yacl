// Copyright 2019 Ant Group Co., Ltd.
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

#include "yacl/link/transport/brpc_link.h"

#include <exception>
#include <memory>
#include <utility>

#include "spdlog/spdlog.h"

#include "yacl/base/exception.h"
#include "yacl/link/transport/channel.h"

#include "interconnection/link/transport.pb.h"

namespace yacl::link::transport {

namespace ic = org::interconnection;
namespace ic_pb = org::interconnection::link;
namespace internal {

class ReceiverServiceImpl : public ic_pb::ReceiverService {
 public:
  explicit ReceiverServiceImpl(
      std::map<size_t, std::shared_ptr<Channel>> listener)
      : listeners_(std::move(listener)) {}

  void Push(::google::protobuf::RpcController* /*cntl_base*/,
            const ic_pb::PushRequest* request, ic_pb::PushResponse* response,
            ::google::protobuf::Closure* done) override {
    brpc::ClosureGuard done_guard(done);

    const size_t sender_rank = request->sender_rank();
    auto iter = listeners_.find(sender_rank);
    if (iter == listeners_.end()) {
      response->mutable_header()->set_error_code(
          ic::ErrorCode::UNEXPECTED_ERROR);
      response->mutable_header()->set_error_msg(fmt::format(
          "dispatch error, key={}, error=listener rank={} not found",
          request->key(), sender_rank));
    } else {
      iter->second->OnRequest(*request, response);
    }
  }

 protected:
  std::map<size_t, std::shared_ptr<Channel>> listeners_;
};

}  // namespace internal

void ReceiverLoopBrpc::StopImpl() {
  server_.Stop(0);
  server_.Join();
}

ReceiverLoopBrpc::~ReceiverLoopBrpc() { StopImpl(); }

void ReceiverLoopBrpc::Stop() { StopImpl(); }

std::string ReceiverLoopBrpc::Start(const std::string& host,
                                    const SSLOptions* ssl_opts) {
  if (server_.IsRunning()) {
    YACL_THROW_LOGIC_ERROR("brpc server is already running");
  }

  auto svc = std::make_unique<internal::ReceiverServiceImpl>(listeners_);
  if (server_.AddService(svc.get(), brpc::SERVER_OWNS_SERVICE) == 0) {
    // Once add service succeed, give up ownership
    static_cast<void>(svc.release());
  } else {
    YACL_THROW_IO_ERROR("brpc server failed to add msg service");
  }

  // Start the server.
  brpc::ServerOptions options;
  options.has_builtin_services = false;
  options.h2_settings.stream_window_size = brpc::H2Settings::MAX_WINDOW_SIZE;
  options.h2_settings.connection_window_size =
      brpc::H2Settings::MAX_WINDOW_SIZE;
  if (ssl_opts != nullptr) {
    options.mutable_ssl_options()->default_cert.certificate =
        ssl_opts->cert.certificate_path;
    options.mutable_ssl_options()->default_cert.private_key =
        ssl_opts->cert.private_key_path;
    options.mutable_ssl_options()->verify.verify_depth =
        ssl_opts->verify.verify_depth;
    options.mutable_ssl_options()->verify.ca_file_path =
        ssl_opts->verify.ca_file_path;
  }
  if (server_.Start(host.data(), &options) != 0) {
    YACL_THROW_IO_ERROR("brpc server failed start");
  }

  return butil::endpoint2str(server_.listen_address()).c_str();
}

void BrpcLink::SetPeerHost(const std::string& peer_host,
                           const SSLOptions* ssl_opts) {
  auto brpc_channel = std::make_unique<brpc::Channel>();
  const auto load_balancer = "";
  brpc::ChannelOptions options;
  {
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
  int res = brpc_channel->Init(peer_host.c_str(), load_balancer, &options);
  if (res != 0) {
    YACL_THROW_NETWORK_ERROR("Fail to initialize channel, host={}, err_code={}",
                             peer_host, res);
  }

  delegate_channel_ = std::move(brpc_channel);
  peer_host_ = peer_host;
}

void BrpcLink::SendRequest(const Request& request, uint32_t timeout) const {
  ic_pb::PushResponse response;
  brpc::Controller cntl;
  cntl.ignore_eovercrowded();
  if (timeout != 0) {
    cntl.set_timeout_ms(timeout);
  }
  ic_pb::ReceiverService::Stub stub(delegate_channel_.get());
  stub.Push(&cntl, static_cast<const ic_pb::PushRequest*>(&request), &response,
            nullptr);
  // handle failures.
  if (cntl.Failed()) {
    ThrowLinkErrorByBrpcCntl(cntl);
  }

  if (response.header().error_code() != ic::ErrorCode::OK) {
    YACL_THROW("send, peer failed message={}", response.header().error_msg());
  }
}

}  // namespace yacl::link::transport
