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

#include "yacl/link/transport/channel_chunked_base.h"

#include <exception>
#include <memory>
#include <utility>

#include "absl/strings/match.h"
#include "fmt/ostream.h"
#include "spdlog/spdlog.h"

#include "yacl/base/exception.h"

#include "interconnection/link/transport.pb.h"

namespace brpc::policy {

DECLARE_int32(h2_client_stream_window_size);

}

namespace fmt {
template <>
struct formatter<org::interconnection::link::TransType> : ostream_formatter {};
}  // namespace fmt

namespace yacl::link::transport {

namespace ic = org::interconnection;
namespace ic_pb = org::interconnection::link;

class SendChunkedWindow
    : public std::enable_shared_from_this<SendChunkedWindow> {
 public:
  explicit SendChunkedWindow(int64_t limit) : parallel_limit_(limit) {
    YACL_ENFORCE(parallel_limit_ > 0);
  }

  void OnPushDone(std::optional<std::exception> e) noexcept {
    std::unique_lock<bthread::Mutex> lock(mutex_);
    running_push_--;

    if (e.has_value()) {
      async_exception_ = std::move(e);
    }
    cond_.notify_all();
  }

  void Finished() {
    std::unique_lock<bthread::Mutex> lock(mutex_);
    while (running_push_ != 0) {
      cond_.wait(lock);
      if (async_exception_.has_value()) {
        throw async_exception_.value();
      }
    }
  }

  class Token {
   public:
    explicit Token(std::shared_ptr<SendChunkedWindow> window)
        : window_(std::move(window)) {}

    void SetException(std::optional<std::exception>& e) {
      if (!e.has_value()) {
        return;
      }
      exception_ = std::move(e);
    }

    ~Token() { window_->OnPushDone(exception_); }

   private:
    std::shared_ptr<SendChunkedWindow> window_;
    std::optional<std::exception> exception_;
  };

  std::unique_ptr<Token> GetToken() {
    std::unique_lock<bthread::Mutex> lock(mutex_);
    running_push_++;

    while (running_push_ >= parallel_limit_) {
      cond_.wait(lock);
      if (async_exception_.has_value()) {
        throw async_exception_.value();
      }
    }

    return std::make_unique<Token>(this->shared_from_this());
  }

 private:
  const int64_t parallel_limit_;
  int64_t running_push_ = 0;
  bthread::Mutex mutex_;
  bthread::ConditionVariable cond_;
  std::optional<std::exception> async_exception_;
};

class ChunkedMessage {
 public:
  explicit ChunkedMessage(int64_t message_length) : message_(message_length) {}

  void AddChunk(int64_t offset, ByteContainerView data) {
    std::unique_lock<bthread::Mutex> lock(mutex_);
    if (received_.emplace(offset).second) {
      std::memcpy(message_.data<std::byte>() + offset, data.data(),
                  data.size());
      bytes_written_ += data.size();
    }
  }

  bool IsFullyFilled() {
    std::unique_lock<bthread::Mutex> lock(mutex_);
    return bytes_written_ == message_.size();
  }

  Buffer&& Reassemble() {
    std::unique_lock<bthread::Mutex> lock(mutex_);
    return std::move(message_);
  }

 protected:
  bthread::Mutex mutex_;
  std::set<int64_t> received_;
  // chunk index to value.
  int64_t bytes_written_{0};
  Buffer message_;
};

void ChannelChunkedBase::SendImpl(const std::string& key,
                                  ByteContainerView value) {
  SendImpl(key, value, 0);
}

void ChannelChunkedBase::SendImpl(const std::string& key,
                                  ByteContainerView value, uint32_t timeout) {
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

  PushRequest(request, timeout);
}

class SendChunkedTask {
 public:
  SendChunkedTask(ChannelChunkedBase* channel,
                  std::unique_ptr<SendChunkedWindow::Token> token,
                  std::unique_ptr<ic_pb::PushRequest> request)
      : channel_(channel),
        token_(std::move(token)),
        request_(std::move(request)) {
    YACL_ENFORCE(request_, "request is null");
    YACL_ENFORCE(token_, "token is null");
    YACL_ENFORCE(channel_, "channel is null");
  }

  static void* Proc(void* param) {
    std::unique_ptr<SendChunkedTask> task(static_cast<SendChunkedTask*>(param));
    std::optional<std::exception> except;
    try {
      task->channel_->PushRequest(*(task->request_), 0);
    } catch (Exception& e) {
      except = e;
      task->token_->SetException(except);
    }

    return nullptr;
  };

 private:
  ChannelChunkedBase* channel_;
  std::unique_ptr<SendChunkedWindow::Token> token_;
  std::unique_ptr<ic_pb::PushRequest> request_;
};

void ChannelChunkedBase::SendChunked(const std::string& key,
                                     ByteContainerView value) {
  const size_t bytes_per_chunk = options_.http_max_payload_size;
  const size_t num_bytes = value.size();
  const size_t num_chunks = (num_bytes + bytes_per_chunk - 1) / bytes_per_chunk;

  constexpr uint32_t kParallelSize = 8;
  auto window = std::make_shared<SendChunkedWindow>(kParallelSize);

  for (size_t chunk_idx = 0; chunk_idx < num_chunks; chunk_idx++) {
    const size_t chunk_offset = chunk_idx * bytes_per_chunk;

    auto request = std::make_unique<ic_pb::PushRequest>();
    {
      request->set_sender_rank(self_rank_);
      request->set_key(key);
      request->set_value(
          value.data() + chunk_offset,
          std::min(bytes_per_chunk, value.size() - chunk_offset));
      request->set_trans_type(ic_pb::TransType::CHUNKED);
      request->mutable_chunk_info()->set_chunk_offset(chunk_offset);
      request->mutable_chunk_info()->set_message_length(num_bytes);
    }

    auto task = std::make_unique<SendChunkedTask>(this, window->GetToken(),
                                                  std::move(request));
    bthread_t tid;
    if (bthread_start_background(&tid, nullptr, SendChunkedTask::Proc,
                                 task.get()) == 0) {
      (void)task.release();
    } else {
      YACL_THROW("Start bthread error for Chunk (key: {}, {} of {}) error", key,
                 chunk_idx, num_chunks);
    }
  }
  window->Finished();
}

void ChannelChunkedBase::OnRequest(const ic_pb::PushRequest* request,
                                   ic_pb::PushResponse* response) {
  auto trans_type = request->trans_type();

  response->mutable_header()->set_error_code(ic::ErrorCode::OK);
  response->mutable_header()->set_error_msg("");
  // dispatch the message
  if (trans_type == ic_pb::TransType::MONO) {
    OnMessage(request->key(), request->value());
  } else if (trans_type == ic_pb::TransType::CHUNKED) {
    const auto& chunk = request->chunk_info();
    OnChunkedMessage(request->key(), request->value(), chunk.chunk_offset(),
                     chunk.message_length());
  } else {
    response->mutable_header()->set_error_code(ic::ErrorCode::INVALID_REQUEST);
    response->mutable_header()->set_error_msg(
        fmt::format("unrecongnized trans type={}, from rank={}", trans_type,
                    request->sender_rank()));
  }
}

void ChannelChunkedBase::OnChunkedMessage(const std::string& key,
                                          ByteContainerView value,
                                          size_t offset, size_t total_length) {
  if (offset + value.size() > total_length) {
    YACL_THROW_LOGIC_ERROR(
        "invalid chunk info, offset={}, chun size = {}, total_length={}",
        offset, value.size(), total_length);
  }

  bool should_reassemble = false;
  std::shared_ptr<ChunkedMessage> data;
  {
    std::unique_lock<bthread::Mutex> lock(chunked_values_mutex_);
    auto itr = chunked_values_.find(key);
    if (itr == chunked_values_.end()) {
      itr = chunked_values_
                .emplace(key, std::make_shared<ChunkedMessage>(total_length))
                .first;
    }

    data = itr->second;
    data->AddChunk(offset, value);

    if (data->IsFullyFilled()) {
      chunked_values_.erase(itr);

      // only one thread do the reassemble
      should_reassemble = true;
    }
  }

  if (should_reassemble) {
    OnMessage(key, data->Reassemble());
  }
}

auto ChannelChunkedBase::MakeOptions(
    Options& default_opt, uint32_t http_timeout_ms,
    uint32_t http_max_payload_size, const std::string& brpc_channel_protocol,
    const std::string& brpc_channel_connection_type) -> Options {
  auto opts = default_opt;
  if (http_timeout_ms != 0) {
    opts.http_timeout_ms = http_timeout_ms;
  }
  if (http_max_payload_size != 0) {
    opts.http_max_payload_size = http_max_payload_size;
  }
  if (!brpc_channel_protocol.empty()) {
    opts.channel_protocol = brpc_channel_protocol;
  }

  if (absl::StartsWith(opts.channel_protocol, "h2")) {
    YACL_ENFORCE(opts.http_max_payload_size > 4096,
                 "http_max_payload_size is too small");
    YACL_ENFORCE(
        opts.http_max_payload_size < std::numeric_limits<int32_t>::max(),
        "http_max_payload_size is too large");
    // if use h2 protocol (h2 or h2:grpc), need to change h2 window size too,
    // use http_max_payload_size as h2's window size, then reserve 4kb buffer
    // for protobuf header
    brpc::policy::FLAGS_h2_client_stream_window_size =
        static_cast<int32_t>(opts.http_max_payload_size);
    opts.http_max_payload_size -= 4096;
  }

  if (!brpc_channel_connection_type.empty()) {
    opts.channel_connection_type = brpc_channel_connection_type;
  }

  return opts;
}

}  // namespace yacl::link::transport
