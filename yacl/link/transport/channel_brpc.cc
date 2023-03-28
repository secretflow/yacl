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

#include <exception>

#include "spdlog/spdlog.h"

#include "yacl/base/exception.h"

#include "interconnection/link/transport.pb.h"

namespace yacl::link {

namespace ic = org::interconnection;
namespace ic_pb = org::interconnection::link;

namespace internal {

class ReceiverServiceImpl : public ic_pb::ReceiverService {
 public:
  explicit ReceiverServiceImpl(
      std::map<size_t, std::shared_ptr<IChannel>> listener)
      : listeners_(std::move(listener)) {}

  void Push(::google::protobuf::RpcController* /*cntl_base*/,
            const ic_pb::PushRequest* request, ic_pb::PushResponse* response,
            ::google::protobuf::Closure* done) override {
    brpc::ClosureGuard done_guard(done);

    try {
      const size_t sender_rank = request->sender_rank();
      const auto& trans_type = request->trans_type();

      // dispatch the message
      if (trans_type == ic_pb::TransType::MONO) {
        OnRpcCall(sender_rank, request->key(), request->value());
      } else if (trans_type == ic_pb::TransType::CHUNKED) {
        const auto& chunk = request->chunk_info();
        OnRpcCall(sender_rank, request->key(), request->value(),
                  chunk.chunk_offset(), chunk.message_length());
      } else {
        response->mutable_header()->set_error_code(
            ic::ErrorCode::INVALID_REQUEST);
        response->mutable_header()->set_error_msg(
            fmt::format("unrecongnized trans type={}, from rank={}", trans_type,
                        sender_rank));
      }
      response->mutable_header()->set_error_code(ic::ErrorCode::OK);
      response->mutable_header()->set_error_msg("");
    } catch (const std::exception& e) {
      response->mutable_header()->set_error_code(
          ic::ErrorCode::UNEXPECTED_ERROR);
      response->mutable_header()->set_error_msg(fmt::format(
          "dispatch error, key={}, error={}", request->key(), e.what()));
    }
  }

 protected:
  std::map<size_t, std::shared_ptr<IChannel>> listeners_;

 private:
  void OnRpcCall(size_t src_rank, const std::string& key,
                 const std::string& value) {
    auto itr = listeners_.find(src_rank);
    if (itr == listeners_.end()) {
      YACL_THROW_LOGIC_ERROR("dispatch error, listener rank={} not found",
                             src_rank);
    }
    // TODO: maybe need std::string_view interface to avoid memcpy
    return itr->second->OnMessage(key, value);
  }

  void OnRpcCall(size_t src_rank, const std::string& key,
                 const std::string& value, size_t offset, size_t total_length) {
    auto itr = listeners_.find(src_rank);
    if (itr == listeners_.end()) {
      YACL_THROW_LOGIC_ERROR("dispatch error, listener rank={} not found",
                             src_rank);
    }
    auto comm_brpc = std::dynamic_pointer_cast<ChannelBrpc>(itr->second);
    // TODO: maybe need std::string_view interface to avoid memcpy
    comm_brpc->OnChunkedMessage(key, value, offset, total_length);
  }
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

namespace {

// TODO: move this to somewhere-else.
class BatchDesc {
 protected:
  size_t batch_idx_;
  size_t batch_size_;
  size_t total_size_;

 public:
  BatchDesc(size_t batch_idx, size_t batch_size, size_t total_size)
      : batch_idx_(batch_idx),
        batch_size_(batch_size),
        total_size_(total_size) {}

  // return the index of this batch.
  size_t Index() const { return batch_idx_; }

  // return the offset of the first element in this batch.
  size_t Begin() const { return batch_idx_ * batch_size_; }

  // return the offset after last element in this batch.
  size_t End() const { return std::min(Begin() + batch_size_, total_size_); }

  // return the size of this batch.
  size_t Size() const { return End() - Begin(); }

  std::string ToString() const { return "B:" + std::to_string(batch_idx_); };
};

class OnPushDone : public google::protobuf::Closure {
 public:
  explicit OnPushDone(std::shared_ptr<ChannelBrpc> channel)
      : channel_(std::move(channel)) {
    channel_->AddAsyncCount();
  }

  ~OnPushDone() override {
    try {
      channel_->SubAsyncCount();
    } catch (std::exception& e) {
      SPDLOG_INFO(e.what());
    }
  }

  void Run() override {
    std::unique_ptr<OnPushDone> self_guard(this);

    if (cntl_.Failed()) {
      SPDLOG_WARN("send, rpc failed={}, message={}", cntl_.ErrorCode(),
                  cntl_.ErrorText());
    } else if (response_.header().error_code() != ic::ErrorCode::OK) {
      SPDLOG_WARN("send, peer failed message={}",
                  response_.header().error_msg());
    }
  }

  ic_pb::PushResponse response_;
  brpc::Controller cntl_;
  std::shared_ptr<ChannelBrpc> channel_;
};

}  // namespace

void ChannelBrpc::SetPeerHost(const std::string& peer_host,
                              const SSLOptions* ssl_opts) {
  auto brpc_channel = std::make_unique<brpc::Channel>();
  const auto load_balancer = "";
  brpc::ChannelOptions options;
  {
    options.protocol = options_.channel_protocol;
    options.connection_type = options_.channel_connection_type;
    options.connect_timeout_ms = 20000;
    options.timeout_ms = options_.http_timeout_ms;
    options.max_retry = 3;
    // options.retry_policy = DefaultRpcRetryPolicy();
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

  channel_ = std::move(brpc_channel);
  peer_host_ = peer_host;
}

namespace {

struct SendChunckedBrpcTask {
  std::shared_ptr<ChannelBrpc> channel;
  std::string key;
  Buffer value;

  SendChunckedBrpcTask(std::shared_ptr<ChannelBrpc> _channel, std::string _key,
                       Buffer _value)
      : channel(std::move(_channel)),
        key(std::move(_key)),
        value(std::move(_value)) {
    channel->AddAsyncCount();
  }

  ~SendChunckedBrpcTask() {
    try {
      channel->SubAsyncCount();
    } catch (std::exception& e) {
      SPDLOG_INFO(e.what());
    }
  }

  static void* Proc(void* args) {
    // take ownership of task.
    std::unique_ptr<SendChunckedBrpcTask> task(
        static_cast<SendChunckedBrpcTask*>(args));

    task->channel->SendChunked(task->key, task->value);
    return nullptr;
  }
};

}  // namespace

void ChannelBrpc::AddAsyncCount() {
  std::unique_lock<bthread::Mutex> lock(wait_async_mutex_);
  running_async_count_++;
}

void ChannelBrpc::SubAsyncCount() {
  std::unique_lock<bthread::Mutex> lock(wait_async_mutex_);
  YACL_ENFORCE(running_async_count_ > 0);
  running_async_count_--;
  if (running_async_count_ == 0) {
    wait_async_cv_.notify_all();
  }
}

void ChannelBrpc::WaitAsyncSendToFinish() {
  std::unique_lock<bthread::Mutex> lock(wait_async_mutex_);
  while (running_async_count_ > 0) {
    wait_async_cv_.wait(lock);
  }
}

template <class ValueType>
void ChannelBrpc::SendAsyncInternal(const std::string& key, ValueType&& value) {
  if (value.size() > options_.http_max_payload_size) {
    auto btask = std::make_unique<SendChunckedBrpcTask>(
        this->shared_from_this(), key, Buffer(std::forward<ValueType>(value)));

    // bthread run in 'detached' mode, we will never wait for it.
    bthread_t tid;
    if (bthread_start_background(&tid, nullptr, SendChunckedBrpcTask::Proc,
                                 btask.get()) == 0) {
      // bthread takes the ownership, release it.
      static_cast<void>(btask.release());
    } else {
      YACL_THROW("failed to push async sending job to bthread");
    }

    return;
  }

  ic_pb::PushRequest request;
  {
    request.set_sender_rank(self_rank_);
    request.set_key(key);
    request.set_value(reinterpret_cast<const char*>(value.data()),
                      value.size());
    request.set_trans_type(ic_pb::TransType::MONO);
  }

  OnPushDone* done = new OnPushDone(shared_from_this());
  ic_pb::ReceiverService::Stub stub(channel_.get());
  done->cntl_.ignore_eovercrowded();
  stub.Push(&done->cntl_, &request, &done->response_, done);
}

void ChannelBrpc::SendAsyncImpl(const std::string& key, Buffer&& value) {
  SendAsyncInternal(key, std::move(value));
}

void ChannelBrpc::SendAsyncImpl(const std::string& key,
                                ByteContainerView value) {
  SendAsyncInternal(key, value);
}

void ChannelBrpc::SendImpl(const std::string& key, ByteContainerView value) {
  SendImpl(key, value, 0);
}

void ChannelBrpc::SendImpl(const std::string& key, ByteContainerView value,
                           uint32_t timeout) {
  if (value.size() > options_.http_max_payload_size) {
    SendChunked(key, value);
    return;
  }

  ic_pb::PushRequest request;
  {
    request.set_sender_rank(self_rank_);
    request.set_key(key);
    request.set_value(value.data(), value.size());
    request.set_trans_type(ic_pb::TransType::MONO);
  }

  ic_pb::PushResponse response;
  brpc::Controller cntl;
  if (timeout != 0) {
    cntl.set_timeout_ms(timeout);
  }
  ic_pb::ReceiverService::Stub stub(channel_.get());
  stub.Push(&cntl, &request, &response, nullptr);

  // handle failures.
  if (cntl.Failed()) {
    YACL_THROW_NETWORK_ERROR("send, rpc failed={}, message={}",
                             cntl.ErrorCode(), cntl.ErrorText());
  }

  if (response.header().error_code() != ic::ErrorCode::OK) {
    YACL_THROW("send, peer failed message={}", response.header().error_msg());
  }
}

// See: chunked streamming
//   https://en.wikipedia.org/wiki/Chunked_transfer_encoding
// See: Brpc does NOT support POST chunked.
//   https://github.com/apache/incubator-brpc/blob/master/docs/en/http_client.md
void ChannelBrpc::SendChunked(const std::string& key, ByteContainerView value) {
  const size_t bytes_per_chunk = options_.http_max_payload_size;
  const size_t num_bytes = value.size();
  const size_t num_chunks = (num_bytes + bytes_per_chunk - 1) / bytes_per_chunk;

  constexpr uint32_t kParallelSize = 10;
  const size_t batch_size = kParallelSize;
  const size_t num_batches = (num_chunks + batch_size - 1) / batch_size;

  for (size_t batch_idx = 0; batch_idx < num_batches; batch_idx++) {
    const BatchDesc batch(batch_idx, batch_size, num_chunks);

    // See: "半同步“ from
    // https://github.com/apache/incubator-brpc/blob/master/docs/cn/client.md
    std::vector<brpc::Controller> cntls(batch.Size());
    std::vector<ic_pb::PushResponse> responses(batch.Size());

    // fire batched chunk requests.
    for (size_t idx = 0; idx < batch.Size(); idx++) {
      const size_t chunk_idx = batch.Begin() + idx;
      const size_t chunk_offset = chunk_idx * bytes_per_chunk;

      ic_pb::PushRequest request;
      {
        request.set_sender_rank(self_rank_);
        request.set_key(key);
        request.set_value(
            value.data() + chunk_offset,
            std::min(bytes_per_chunk, value.size() - chunk_offset));
        request.set_trans_type(ic_pb::TransType::CHUNKED);
        request.mutable_chunk_info()->set_chunk_offset(chunk_offset);
        request.mutable_chunk_info()->set_message_length(num_bytes);
      }

      auto& cntl = cntls[idx];
      cntl.ignore_eovercrowded();
      auto& response = responses[idx];
      ic_pb::ReceiverService::Stub stub(channel_.get());
      stub.Push(&cntl, &request, &response, brpc::DoNothing());
    }

    for (size_t idx = 0; idx < batch.Size(); idx++) {
      brpc::Join(cntls[idx].call_id());
    }

    for (size_t idx = 0; idx < batch.Size(); idx++) {
      const size_t chunk_idx = batch.Begin() + idx;
      const auto& cntl = cntls[idx];
      const auto& response = responses[idx];
      if (cntl.Failed()) {
        YACL_THROW_NETWORK_ERROR(
            "send key={} (chunked {} out of {}) rpc failed: {}, message={}",
            key, chunk_idx + 1, num_chunks, cntl.ErrorCode(), cntl.ErrorText());
      } else if (response.header().error_code() != ic::ErrorCode::OK) {
        YACL_THROW(
            "send key={} (chunked {} out of {}) response failed, message={}",
            key, chunk_idx + 1, num_chunks, response.header().error_msg());
      }
    }
  }
}

}  // namespace yacl::link
