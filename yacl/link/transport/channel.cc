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

#include <set>

#include "spdlog/spdlog.h"

#include "yacl/base/buffer.h"
#include "yacl/base/byte_container_view.h"
#include "yacl/base/exception.h"

namespace yacl::link {

// use acsii control code inside ack/fin msg key.
// avoid conflict to normal msg key.
static const std::string kAckKey{'A', 'C', 'K', '\x01', '\x00'};
static const std::string kFinKey{'F', 'I', 'N', '\x01', '\x00'};

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

Buffer ChannelBase::Recv(const std::string& key) {
  YACL_ENFORCE(key != kAckKey && key != kFinKey,
               "For developer: pls use another key for normal message.");

  Buffer value;
  {
    std::unique_lock<bthread::Mutex> lock(msg_mutex_);
    auto stop_waiting = [&] {
      auto itr = this->msg_db_.find(key);
      if (itr == this->msg_db_.end()) {
        return false;
      } else {
        value = std::move(itr->second);
        this->msg_db_.erase(itr);
        return true;
      }
    };
    while (!stop_waiting()) {
      //                              timeout_us
      if (msg_db_cond_.wait_for(lock, recv_timeout_ms_ * 1000) == ETIMEDOUT) {
        YACL_THROW_IO_ERROR("Get data timeout, key={}", key);
      }
    }
  }
  SendAsyncImpl(kAckKey, ByteContainerView{});

  return value;
}

template <typename T>
void ChannelBase::OnNormalMessage(const std::string& key, T&& v) {
  received_msg_count_++;
  if (!waiting_finish_) {
    if (!msg_db_.emplace(key, std::forward<T>(v)).second) {
      SendAsyncImpl(kAckKey, ByteContainerView{});
      SPDLOG_WARN("Duplicate key {}", key);
    }
  } else {
    SendAsyncImpl(kAckKey, ByteContainerView{});
    SPDLOG_WARN("Asymmetric logic exist, auto ack key {}", key);
  }
  msg_db_cond_.notify_all();
}

void ChannelBase::OnMessage(const std::string& key, ByteContainerView value) {
  std::unique_lock<bthread::Mutex> lock(msg_mutex_);
  if (key == kAckKey) {
    ack_msg_count_++;
    ack_fin_cond_.notify_all();
  } else if (key == kFinKey) {
    YACL_ENFORCE(value.size() == sizeof(size_t));
    if (!received_fin_) {
      received_fin_ = true;
      std::memcpy(&peer_sent_msg_count_, value.data(), sizeof(size_t));
      ack_fin_cond_.notify_all();
    }
  } else {
    OnNormalMessage(key, value);
  }
}

void ChannelBase::OnChunkedMessage(const std::string& key,
                                   ByteContainerView value, size_t offset,
                                   size_t total_length) {
  YACL_ENFORCE(key != kAckKey && key != kFinKey,
               "For developer: pls use another key for normal message.");
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
    // notify new value arrived.
    std::unique_lock<bthread::Mutex> lock(msg_mutex_);
    OnNormalMessage(key, data->Reassemble());
  }
}

void ChannelBase::SetRecvTimeout(uint32_t recv_timeout_ms) {
  recv_timeout_ms_ = recv_timeout_ms;
}

uint32_t ChannelBase::GetRecvTimeout() const { return recv_timeout_ms_; }

void ChannelBase::SendAsync(const std::string& key, ByteContainerView value) {
  YACL_ENFORCE(key != kAckKey && key != kFinKey,
               "For developer: pls use another key for normal message.");
  SendAsyncImpl(key, value);
  ThrottleWindowWait(sent_msg_count_.fetch_add(1) + 1);
}

void ChannelBase::SendAsync(const std::string& key, Buffer&& value) {
  YACL_ENFORCE(key != kAckKey && key != kFinKey,
               "For developer: pls use another key for normal message.");
  SendAsyncImpl(key, std::move(value));
  ThrottleWindowWait(sent_msg_count_.fetch_add(1) + 1);
}

void ChannelBase::Send(const std::string& key, ByteContainerView value) {
  YACL_ENFORCE(key != kAckKey && key != kFinKey,
               "For developer: pls use another key for normal message.");
  SendImpl(key, value);
  ThrottleWindowWait(sent_msg_count_.fetch_add(1) + 1);
}

void ChannelBase::Send(const std::string& key, ByteContainerView value,
                       uint32_t timeout) {
  YACL_ENFORCE(key != kAckKey && key != kFinKey,
               "For developer: pls use another key for normal message.");
  SendImpl(key, value, timeout);
  ThrottleWindowWait(sent_msg_count_.fetch_add(1) + 1);
}

// all sender thread wait on it's send order.
void ChannelBase::ThrottleWindowWait(size_t wait_count) {
  if (throttle_window_size_ == 0) {
    return;
  }
  std::unique_lock<bthread::Mutex> lock(msg_mutex_);
  while (!((throttle_window_size_ == 0) ||
           (ack_msg_count_ + throttle_window_size_ > wait_count))) {
    //                               timeout_us
    if (ack_fin_cond_.wait_for(lock, recv_timeout_ms_ * 1000) == ETIMEDOUT) {
      YACL_THROW_IO_ERROR("Throttle window wait timeout");
    }
  }
}

void ChannelBase::WaitForFinAndFlyingMsg() {
  size_t sent_msg_count = sent_msg_count_;
  SendAsyncImpl(
      kFinKey, ByteContainerView{reinterpret_cast<const char*>(&sent_msg_count),
                                 sizeof(size_t)});
  {
    std::unique_lock<bthread::Mutex> lock(msg_mutex_);
    while (!received_fin_) {
      ack_fin_cond_.wait(lock);
    }
  }
  {
    std::unique_lock<bthread::Mutex> lock(msg_mutex_);
    while (received_msg_count_ < peer_sent_msg_count_) {
      msg_db_cond_.wait(lock);
    }
    if (received_msg_count_ > peer_sent_msg_count_) {
      // brpc will reply msg if connection is break (not timeout!), may cause
      // duplicate msg. e.g. alice's gateway pod is migrated before revice bob's
      // responce. in this rare case we may revice one msg more than once.
      // received msg count will greater then expected count.
      SPDLOG_WARN("duplicated msg exist during running");
    }
  }
}

void ChannelBase::StopReceivingAndAckUnreadMsgs() {
  std::unique_lock<bthread::Mutex> lock(msg_mutex_);
  waiting_finish_ = true;
  for (auto& msg : msg_db_) {
    SPDLOG_WARN("Asymmetric logic exist, clear unread key {}", msg.first);
    SendAsyncImpl(kAckKey, ByteContainerView{});
  }
  msg_db_.clear();
}

void ChannelBase::WaitForFlyingAck() {
  std::unique_lock<bthread::Mutex> lock(msg_mutex_);
  while (ack_msg_count_ < sent_msg_count_) {
    ack_fin_cond_.wait(lock);
  }

  if (ack_msg_count_ > sent_msg_count_) {
    // brpc will reply msg if connection is break (not timeout!), may cause
    // duplicate msg. e.g. alice's gateway pod is migrated before revice bob's
    // responce. in this rare case we may revice one msg more than once.
    // received msg count will greater then expected count.
    SPDLOG_WARN("duplicated msg exist during running");
  }
}

void ChannelBase::WaitLinkTaskFinish() {
  // 4 steps to total stop link.
  // send ack for msg exist in msg_db_ that unread by up layer logic.
  // stop OnMessage & auto ack all normal msg from now on.
  StopReceivingAndAckUnreadMsgs();
  // wait for last fin msg contain peer's send msg count.
  // then check if received count is equal to peer's send count.
  // we can not close server port if peer still sending msg
  // or peer's gateway will throw 504 error.
  WaitForFinAndFlyingMsg();
  // make sure all Async send is finished.
  WaitAsyncSendToFinish();
  // at least, wait for all ack msg.
  WaitForFlyingAck();
  // after all, we can safely close server port and exit.
}

void ReceiverLoopBase::AddListener(size_t rank,
                                   std::shared_ptr<IChannel> listener) {
  auto ret = listeners_.emplace(rank, std::move(listener));
  if (!ret.second) {
    YACL_THROW_LOGIC_ERROR("duplicated listener for rank={}", rank);
  }
}

}  // namespace yacl::link
