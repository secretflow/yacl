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

#include "absl/strings/numbers.h"
#include "spdlog/spdlog.h"

#include "yacl/base/buffer.h"
#include "yacl/base/byte_container_view.h"
#include "yacl/base/exception.h"

namespace yacl::link {

namespace {
// use acsii control code inside ack/fin msg key.
// avoid conflict to normal msg key.
const std::string kAckKey{'A', 'C', 'K', '\x01', '\x02'};
const std::string kFinKey{'F', 'I', 'N', '\x01', '\x02'};
const std::string kSeqKey{'\x01', '\x02'};

void NormalMessageKeyEnforce(std::string_view k) {
  YACL_ENFORCE(!k.empty(), "do not use empty key");
  YACL_ENFORCE(k.find(kSeqKey) == k.npos,
               "For developer: pls use another key for normal message.");
}

template <class View>
size_t ViewToSizeT(View v) {
  size_t ret = 0;
  YACL_ENFORCE(absl::SimpleAtoi(
      absl::string_view(reinterpret_cast<const char*>(v.data()), v.size()),
      &ret));
  return ret;
}

std::string BuildChannelKey(std::string_view msg_key, size_t seq_id) {
  return std::string(msg_key) + kSeqKey + std::to_string(seq_id);
}

std::pair<std::string, size_t> SplitChannelKey(std::string_view key) {
  auto pos = key.find(kSeqKey);

  std::pair<std::string, size_t> ret;
  ret.first = key.substr(0, pos);
  ret.second = ViewToSizeT(key.substr(pos + kSeqKey.size()));

  return ret;
}

}  // namespace

class SendTask {
 public:
  std::shared_ptr<ChannelBase> channel_;
  ChannelBase::Message msg_;
  const bool exit_if_async_error_;

  SendTask(std::shared_ptr<ChannelBase> channel, ChannelBase::Message msg,
           bool exit_if_async_error)
      : channel_(std::move(channel)),
        msg_(std::move(msg)),
        exit_if_async_error_(exit_if_async_error) {
    channel_->send_sync_.SendTaskStartNotify();
  }

  ~SendTask() {
    try {
      channel_->send_sync_.SendTaskFinishedNotify(msg_.seq_id_);
    } catch (...) {
      SPDLOG_ERROR("SendTaskFinishedNotify error");
      if (exit_if_async_error_) {
        exit(-1);
      }
    }
  }

  static void* Proc(void* args) {
    // take ownership of task.
    std::unique_ptr<SendTask> task(static_cast<SendTask*>(args));
    try {
      task->channel_->SendImpl(task->msg_.msg_key_, task->msg_.value_);
    } catch (const yacl::Exception& e) {
      SPDLOG_ERROR("SendImpl error {}", e.what());
      if (task->exit_if_async_error_) {
        exit(-1);
      }
    }

    return nullptr;
  }
};

void ChannelBase::StartSendThread() {
  send_thread_ = std::thread([&]() {
    try {
      SendThread();
    } catch (const yacl::Exception& e) {
      SPDLOG_ERROR("SendThread error {}", e.what());
      if (exit_if_async_error_) {
        exit(-1);
      }
    }
  });
}

void ChannelBase::SubmitSendTask(Message&& msg) {
  auto btask = std::make_unique<SendTask>(this->shared_from_this(),
                                          std::move(msg), exit_if_async_error_);
  bthread_t tid;
  if (bthread_start_background(&tid, nullptr, SendTask::Proc, btask.get()) ==
      0) {
    // bthread takes the ownership, release it.
    static_cast<void>(btask.release());
  } else {
    YACL_THROW("failed to push async sending job to bthread");
  }
}

std::optional<ChannelBase::Message> ChannelBase::MessageQueue::Pop(bool block) {
  std::unique_lock<bthread::Mutex> lock(mutex_);
  if (block && queue_.empty()) {
    cond_.wait(lock);
  }

  if (!queue_.empty()) {
    auto msg = std::move(queue_.front());
    queue_.pop();
    return msg;
  } else {
    return {};
  }
}

void ChannelBase::SendThread() {
  while (!send_thread_stoped_.load()) {
    auto msg = msg_queue_.Pop(true);
    if (!msg.has_value()) {
      continue;
    }
    auto seq_id = msg.value().seq_id_;
    SubmitSendTask(std::move(msg.value()));
    ThrottleWindowWait(seq_id);
  }

  // link is closing, send all pending msgs
  while (true) {
    auto msg = msg_queue_.Pop(false);
    if (!msg.has_value()) {
      break;
    }
    SubmitSendTask(std::move(msg.value()));
  }
}

void ChannelBase::SendTaskSynchronizer::SendTaskStartNotify() {
  std::unique_lock<bthread::Mutex> lock(mutex_);
  running_tasks_++;
}

void ChannelBase::SendTaskSynchronizer::SendTaskFinishedNotify(size_t seq_id) {
  std::unique_lock<bthread::Mutex> lock(mutex_);
  running_tasks_--;
  if (seq_id != 0) {
    finished_ids_.Insert(seq_id);
  }
  finished_cond_.notify_all();
}

void ChannelBase::SendTaskSynchronizer::WaitSeqIdSendFinished(size_t seq_id) {
  std::unique_lock<bthread::Mutex> lock(mutex_);
  while (!finished_ids_.Contains(seq_id)) {
    finished_cond_.wait(lock);
  }
}

void ChannelBase::SendTaskSynchronizer::WaitAllSendFinished() {
  std::unique_lock<bthread::Mutex> lock(mutex_);
  while (running_tasks_ > 0) {
    finished_cond_.wait(lock);
  }
}

Buffer ChannelBase::Recv(const std::string& msg_key) {
  NormalMessageKeyEnforce(msg_key);

  Buffer value;
  size_t seq_id = 0;
  {
    std::unique_lock<bthread::Mutex> lock(msg_mutex_);
    auto stop_waiting = [&] {
      auto itr = this->msg_db_.find(msg_key);
      if (itr == this->msg_db_.end()) {
        return false;
      } else {
        std::tie(value, seq_id) = std::move(itr->second);
        this->msg_db_.erase(itr);
        return true;
      }
    };
    while (!stop_waiting()) {
      //                                timeout_us
      if (msg_db_cond_.wait_for(lock, static_cast<int64_t>(recv_timeout_ms_) *
                                          1000) == ETIMEDOUT) {
        YACL_THROW_IO_ERROR("Get data timeout, key={}", msg_key);
      }
    }
  }
  SendAck(seq_id);

  return value;
}

void ChannelBase::SendAck(size_t seq_id) {
  if (seq_id > 0) {
    // 0 seq id use for TestSend/TestRecv, no need to send ack.
    SubmitSendTask(Message(0, kAckKey, Buffer(std::to_string(seq_id))));
  }
}

template <typename T>
void ChannelBase::OnNormalMessage(const std::string& key, T&& v) {
  std::string msg_key;
  size_t seq_id = 0;
  std::tie(msg_key, seq_id) = SplitChannelKey(key);

  if (seq_id > 0 && !received_msg_ids_.Insert(seq_id)) {
    // 0 seq id use for TestSend/TestRecv, skip duplicate test.
    // Duplicate seq id found. may be caused by rpc retry, ignore
    SPDLOG_WARN("Duplicate seq_id found, key {} seq_id {}", msg_key, seq_id);
    return;
  }

  if (!waiting_finish_.load()) {
    auto pair =
        msg_db_.emplace(msg_key, std::make_pair(std::forward<T>(v), seq_id));
    if (seq_id > 0 && !pair.second) {
      YACL_THROW(
          "For developer: BUG! PLS do not use same key for multiple msg, "
          "Duplicate key {} with new seq_id {}, old seq_id {}.",
          msg_key, seq_id, pair.first->second.second);
    }
  } else {
    SendAck(seq_id);
    SPDLOG_WARN("Asymmetric logic exist, auto ack key {} seq_id {}", msg_key,
                seq_id);
  }
  msg_db_cond_.notify_all();
}

void ChannelBase::OnMessage(const std::string& key, ByteContainerView value) {
  std::unique_lock<bthread::Mutex> lock(msg_mutex_);
  if (key == kAckKey) {
    size_t seq_id = ViewToSizeT(value);
    if (received_ack_ids_.Insert(seq_id)) {
      ack_fin_cond_.notify_all();
    } else {
      SPDLOG_WARN("Duplicate ACK id {}", seq_id);
    }
  } else if (key == kFinKey) {
    if (!received_fin_) {
      received_fin_ = true;
      peer_sent_msg_count_ = ViewToSizeT(value);
      ack_fin_cond_.notify_all();
    } else {
      SPDLOG_WARN("Duplicate FIN");
    }
  } else {
    OnNormalMessage(key, value);
  }
}

void ChannelBase::SetRecvTimeout(uint64_t recv_timeout_ms) {
  recv_timeout_ms_ = recv_timeout_ms;
}

uint64_t ChannelBase::GetRecvTimeout() const { return recv_timeout_ms_; }

void ChannelBase::SendAsync(const std::string& msg_key,
                            ByteContainerView value) {
  SendAsync(msg_key, Buffer(value));
}

void ChannelBase::MessageQueue::Push(Message&& msg) {
  std::unique_lock<bthread::Mutex> lock(mutex_);
  queue_.push(std::move(msg));
  cond_.notify_all();
}

void ChannelBase::SendAsync(const std::string& msg_key, Buffer&& value) {
  YACL_ENFORCE(!waiting_finish_.load(),
               "SendAsync is not allowed when channel is closing");
  NormalMessageKeyEnforce(msg_key);
  size_t seq_id = msg_seq_id_.fetch_add(1) + 1;
  auto key = BuildChannelKey(msg_key, seq_id);
  msg_queue_.Push(Message(seq_id, std::move(key), std::move(value)));
}

void ChannelBase::Send(const std::string& msg_key, ByteContainerView value) {
  YACL_ENFORCE(!waiting_finish_.load(),
               "Send is not allowed when channel is closing");
  NormalMessageKeyEnforce(msg_key);
  size_t seq_id = msg_seq_id_.fetch_add(1) + 1;
  auto key = BuildChannelKey(msg_key, seq_id);
  msg_queue_.Push(Message(seq_id, std::move(key), value));
  send_sync_.WaitSeqIdSendFinished(seq_id);
}

void ChannelBase::SendAsyncThrottled(const std::string& msg_key,
                                     ByteContainerView value) {
  SendAsyncThrottled(msg_key, Buffer(value));
}

void ChannelBase::SendAsyncThrottled(const std::string& msg_key,
                                     Buffer&& value) {
  YACL_ENFORCE(!waiting_finish_.load(),
               "SendAsync is not allowed when channel is closing");
  NormalMessageKeyEnforce(msg_key);
  size_t seq_id = msg_seq_id_.fetch_add(1) + 1;
  auto key = BuildChannelKey(msg_key, seq_id);
  msg_queue_.Push(Message(seq_id, std::move(key), std::move(value)));
  ThrottleWindowWait(seq_id);
}

void ChannelBase::TestSend(uint32_t timeout) {
  YACL_ENFORCE(!waiting_finish_.load(),
               "TestSend is not allowed when channel is closing");
  const auto msg_key = fmt::format("connect_{}", self_rank_);
  const auto key = BuildChannelKey(msg_key, 0);
  SendImpl(key, "", timeout);
}

void ChannelBase::TestRecv() {
  const auto msg_key = fmt::format("connect_{}", peer_rank_);
  Recv(msg_key);
}

// all sender thread wait on it's send order.
void ChannelBase::ThrottleWindowWait(size_t wait_count) {
  if (throttle_window_size_ == 0) {
    return;
  }
  std::unique_lock<bthread::Mutex> lock(msg_mutex_);
  while ((throttle_window_size_ != 0) &&
         (received_ack_ids_.Count() + throttle_window_size_ <= wait_count)) {
    //                               timeout_us
    if (ack_fin_cond_.wait_for(
            lock, static_cast<int64_t>(recv_timeout_ms_) * 1000) == ETIMEDOUT) {
      YACL_THROW_IO_ERROR("Throttle window wait timeout");
    }
  }
}

void ChannelBase::WaitAsyncSendToFinish() {
  send_thread_stoped_.store(true);
  msg_queue_.EmptyNotify();
  send_thread_.join();
  send_sync_.WaitAllSendFinished();
}

void ChannelBase::MessageQueue::EmptyNotify() { cond_.notify_all(); }

void ChannelBase::WaitForFinAndFlyingMsg() {
  size_t sent_msg_count = msg_seq_id_;
  SubmitSendTask(Message(0, kFinKey, Buffer(std::to_string(sent_msg_count))));
  {
    std::unique_lock<bthread::Mutex> lock(msg_mutex_);
    while (!received_fin_) {
      ack_fin_cond_.wait(lock);
    }
  }
  {
    std::unique_lock<bthread::Mutex> lock(msg_mutex_);
    if (peer_sent_msg_count_ == 0) {
      // peer send no thing, no need waiting.
      return;
    }
    // wait until recv all msg from 1 to peer_sent_msg_count_
    while (received_msg_ids_.SegmentsCount() > 1 ||
           !received_msg_ids_.Contains(1) ||
           !received_msg_ids_.Contains(peer_sent_msg_count_)) {
      msg_db_cond_.wait(lock);
    }
  }
}

void ChannelBase::StopReceivingAndAckUnreadMsgs() {
  std::unique_lock<bthread::Mutex> lock(msg_mutex_);
  waiting_finish_.store(true);
  for (auto& msg : msg_db_) {
    auto seq_id = msg.second.second;
    SPDLOG_WARN("Asymmetric logic exist, clear unread key {}, seq_id {}",
                msg.first, seq_id);
    SendAck(seq_id);
  }
  msg_db_.clear();
}

void ChannelBase::WaitForFlyingAck() {
  size_t sent_msg_count = msg_seq_id_;
  std::unique_lock<bthread::Mutex> lock(msg_mutex_);
  if (sent_msg_count == 0) {
    // send no thing, no need waiting.
    return;
  }

  // wait until recv all ack from 1 to sent_msg_count
  while (received_ack_ids_.SegmentsCount() > 1 ||
         !received_ack_ids_.Contains(1) ||
         !received_ack_ids_.Contains(sent_msg_count)) {
    ack_fin_cond_.wait(lock);
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

}  // namespace yacl::link
