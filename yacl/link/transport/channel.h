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

#pragma once
#include <atomic>
#include <condition_variable>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <string>
#include <thread>
#include <utility>

#include "brpc/controller.h"
#include "bthread/bthread.h"
#include "bthread/condition_variable.h"
#include "google/protobuf/message.h"
#include "spdlog/spdlog.h"

#include "yacl/base/buffer.h"
#include "yacl/base/byte_container_view.h"
#include "yacl/base/exception.h"
#include "yacl/link/retry_options.h"
#include "yacl/utils/segment_tree.h"

namespace yacl::link::transport {

// A channel is basic interface for p2p communicator.
class IChannel {
 public:
  virtual ~IChannel() = default;

  // send asynchronously.
  // return when the message successfully pushed into the send queue.
  // SendAsync is not reentrant with same key.
  virtual void SendAsync(const std::string& key, ByteContainerView value) = 0;

  virtual void SendAsync(const std::string& key, Buffer&& value) = 0;

  // send asynchronously but with throttled limit.
  // return when 1. the message successfully pushed into the send queue
  //             2. flying/unconsumed messages is under throttled limit.
  // SendAsyncThrottled is not reentrant with same key.
  virtual void SendAsyncThrottled(const std::string& key, Buffer&& value) = 0;

  virtual void SendAsyncThrottled(const std::string& key,
                                  ByteContainerView value) = 0;

  // Send synchronously.
  // return when the message is successfully pushed into peer's recv buffer.
  // Send is not reentrant with same key.
  virtual void Send(const std::string& key, ByteContainerView value) = 0;

  // block waiting message.
  virtual Buffer Recv(const std::string& key) = 0;

  // called by an async dispatcher.
  virtual void OnMessage(const std::string& key, ByteContainerView value) = 0;

  // set receive timeout ms
  virtual void SetRecvTimeout(uint64_t timeout_ms) = 0;

  // get receive timemout ms
  virtual uint64_t GetRecvTimeout() const = 0;

  // wait for all send and rev msg finish
  virtual void WaitLinkTaskFinish() = 0;

  // abort channel immediately
  virtual void Abort() = 0;

  // set send throttle window size
  virtual void SetThrottleWindowSize(size_t) = 0;

  // test if this channel can send a dummy msg to peer.
  // use fixed 0 seq_id as dummy msg's id make this function reentrant.
  // because ConnectToMesh will retry on this multiple times.
  virtual void TestSend(uint32_t timeout) = 0;

  // wait for dummy msg from peer, timeout by recv_timeout_ms_.
  virtual void TestRecv() = 0;

  // set chunk parallel send size
  virtual void SetChunkParallelSendSize(size_t size) = 0;
};

class TransportLink {
 public:
  using Request = ::google::protobuf::Message;
  using Response = ::google::protobuf::Message;

  TransportLink(size_t self_rank, size_t peer_rank)
      : self_rank_(self_rank), peer_rank_(peer_rank) {}

  virtual ~TransportLink() = default;

  virtual size_t GetMaxBytesPerChunk() const = 0;
  virtual void SetMaxBytesPerChunk(size_t bytes) = 0;
  virtual std::unique_ptr<Request> PackMonoRequest(
      const std::string& key, ByteContainerView value) const = 0;
  virtual std::unique_ptr<Request> PackChunkedRequest(
      const std::string& key, ByteContainerView value, size_t offset,
      size_t total_length) const = 0;
  virtual void UnpackMonoRequest(const Request& request, std::string* key,
                                 ByteContainerView* value) const = 0;
  virtual void UnpackChunckRequest(const Request& request, std::string* key,
                                   ByteContainerView* value, size_t* offset,
                                   size_t* total_length) const = 0;
  virtual void FillResponseOk(const Request& request,
                              Response* response) const = 0;
  virtual void FillResponseError(const Request& request,
                                 Response* response) const = 0;
  virtual bool IsChunkedRequest(const Request& request) const = 0;
  virtual bool IsMonoRequest(const Request& request) const = 0;

  virtual void SendRequest(const Request& request,
                           uint32_t timeout_override_ms) const = 0;

  size_t LocalRank() const { return self_rank_; }
  size_t RemoteRank() const { return peer_rank_; }

 protected:
  const size_t self_rank_;
  const size_t peer_rank_;
};

// forward declaractions.
class ChunkedMessage;

class Channel : public IChannel, public std::enable_shared_from_this<Channel> {
 public:
  Channel(std::shared_ptr<TransportLink> delegate, bool exit_if_async_error,
          const RetryOptions& retry_options)
      : exit_if_async_error_(exit_if_async_error),
        link_(std::move(delegate)),
        retry_options_(retry_options) {
    StartSendThread();
  }
  Channel(std::shared_ptr<TransportLink> delegate, size_t recv_timeout_ms,
          bool exit_if_async_error, const RetryOptions& retry_options)
      : recv_timeout_ms_(recv_timeout_ms),
        exit_if_async_error_(exit_if_async_error),
        link_(std::move(delegate)),
        retry_options_(retry_options) {
    StartSendThread();
  }

  ~Channel() override {
    if (!send_thread_stopped_.load()) {
      SPDLOG_WARN(
          "Channel destructor is called before WaitLinkTaskFinish, try "
          "stop send thread");
      try {
        WaitAsyncSendToFinish();
      } catch (const std::exception& e) {
        SPDLOG_ERROR("Stop send thread err {}", e.what());
        if (exit_if_async_error_) {
          exit(-1);
        }
      }
    }
  }

  std::shared_ptr<TransportLink> GetLink() { return link_; }

  // all send interface for normal msg is not reentrant with same key.
  void SendAsync(const std::string& key, ByteContainerView value) final;

  void SendAsync(const std::string& key, Buffer&& value) final;

  void SendAsyncThrottled(const std::string& key, Buffer&& value) final;

  void SendAsyncThrottled(const std::string& key,
                          ByteContainerView value) final;

  void Send(const std::string& key, ByteContainerView value) final;

  Buffer Recv(const std::string& key) override;

  void OnMessage(const std::string& key, ByteContainerView value) override;

  void SetRecvTimeout(uint64_t recv_timeout_ms) override;

  uint64_t GetRecvTimeout() const override;

  void WaitLinkTaskFinish() final;

  // Note: the channel can no longer be used after aborted, otherwise
  // SendAsync/SendAsyncThrottled/Send/Recv/TestSend/TestRecv will throw
  // yacl::LinkAborted.
  void Abort() final;

  void SetThrottleWindowSize(size_t size) final {
    throttle_window_size_ = size;
  }

  // test if this channel can send a dummy msg to peer.
  // use 0 seq_id as dummy msg's id.
  // Reentrancy function for ConnectToMesh test.
  void TestSend(uint32_t timeout) final;

  // wait for dummy msg from peer, timeout by recv_timeout_ms_.
  void TestRecv() final;

  void OnChunkedMessage(const std::string& key, ByteContainerView value,
                        size_t offset, size_t total_length);

  void OnRequest(const ::google::protobuf::Message& request,
                 ::google::protobuf::Message* response);

  void SetChunkParallelSendSize(size_t size) final {
    chunk_parallel_send_size_ = size;
  }

  void SetDisableMsgSeqId(bool disable_msg_seq_id) {
    disable_msg_seq_id_ = disable_msg_seq_id;
  }

  void SendRequestWithRetry(
      const ::google::protobuf::Message& request, uint32_t timeout_override_ms,
      spdlog::level::level_enum log_level = spdlog::level::info) const;

 protected:
  void SendChunked(const std::string& key, ByteContainerView value) const;

  void SendMono(const std::string& key, ByteContainerView value,
                uint32_t timeout_override_ms,
                spdlog::level::level_enum log_level) const;

  void SendImpl(const std::string& key, ByteContainerView value) const {
    SendImpl(key, value, 0, spdlog::level::info);
  }

  void SendImpl(const std::string& key, ByteContainerView value,
                uint32_t timeout_override_ms,
                spdlog::level::level_enum log_level) const {
    YACL_ENFORCE(link_ != nullptr, "delegate has not been setted.");
    SPDLOG_DEBUG("{} send {}", link_->LocalRank(), key);
    if (value.size() > link_->GetMaxBytesPerChunk()) {
      SendChunked(key, value);
    } else {
      SendMono(key, value, timeout_override_ms, log_level);
    }
  }

 private:
  void WaitAsyncSendToFinish();

  void ThrottleWindowWait(size_t);

  void StopReceivingAndAckUnreadMsgs();

  void WaitForFinAndFlyingMsg();

  void WaitForFlyingAck();

  template <typename T>
  void OnNormalMessage(const std::string&, T&&);

  void SendAck(size_t seq_id);

  friend class SendTask;

  struct Message {
    Message() = default;
    // data owned by msg
    explicit Message(size_t s, std::string k, Buffer v)
        : seq_id_(s),
          msg_key_(std::move(k)),
          value_data_(std::move(v)),
          value_(value_data_) {}
    // only get view
    explicit Message(size_t s, std::string k, ByteContainerView v)
        : seq_id_(s), msg_key_(std::move(k)), value_(v) {}

    size_t seq_id_;
    std::string msg_key_;
    Buffer value_data_;
    ByteContainerView value_;
  };

  void StartSendThread();

  void SendThread();

  void SubmitSendTask(Message&& msg);

  class SendTaskSynchronizer {
   public:
    void SendTaskStartNotify();
    void SendTaskFinishedNotify(size_t seq_id);
    void WaitSeqIdSendFinished(size_t seq_id);
    void WaitAllSendFinished();
    void Abort() {
      task_aborting_.store(true);
      finished_cond_.notify_all();
    }

   private:
    bthread::Mutex mutex_;
    size_t running_tasks_ = 0;
    utils::SegmentTree<size_t> finished_ids_;
    bthread::ConditionVariable finished_cond_;
    std::atomic<bool> task_aborting_ = false;
  };

  class MessageQueue {
   public:
    void Push(Message&&);
    std::optional<Message> Pop(bool block);
    void EmptyNotify();

   private:
    bthread::Mutex mutex_;
    std::queue<Message> queue_;
    bthread::ConditionVariable cond_;
    bool stopped_ = false;
  };

 protected:
  uint64_t recv_timeout_ms_ = 3UL * 60 * 1000;  // 3 minites

  MessageQueue send_msgs_;
  std::thread send_thread_;
  std::atomic<bool> send_thread_stopped_ = false;
  SendTaskSynchronizer send_sync_;

  // chunking related.
  bthread::Mutex chunked_values_mutex_;
  std::map<std::string, std::shared_ptr<ChunkedMessage>> chunked_values_;
  std::atomic<uint32_t> chunk_parallel_send_size_ = 8;

  // message database related.
  bthread::Mutex msg_mutex_;
  bthread::ConditionVariable msg_db_cond_;
  // msg_key -> <value, seq_id>
  std::map<std::string, std::pair<Buffer, size_t>> recv_msgs_;

  // for Throttle Window
  std::atomic<size_t> throttle_window_size_ = 0;
  // for WaitLinkTaskFinish
  // if WaitLinkTaskFinish is called.
  // auto ack all normal msg if true.
  std::atomic<bool> waiting_finish_ = false;
  // for Abort
  std::atomic<bool> aborting_ = false;
  // id count for normal msg sent to peer.
  std::atomic<size_t> msg_seq_id_ = 0;
  // ids for received normal msg from peer.
  utils::SegmentTree<size_t> received_msg_ids_;
  // ids for received ack msg from peer.
  utils::SegmentTree<size_t> received_ack_ids_;
  // if peer's fin msg is received.
  bool received_fin_ = false;
  // and how many normal msg sent by peer.
  size_t peer_sent_msg_count_ = 0;
  // cond for ack/fin wait.
  bthread::ConditionVariable ack_fin_cond_;

  const bool exit_if_async_error_;

  std::shared_ptr<TransportLink> link_;

  RetryOptions retry_options_;

  bool disable_msg_seq_id_ = false;
};

// A receiver loop is a thread loop which receives messages from the world.
// It listens message from all over the world and delivers to listeners.
class IReceiverLoop {
 public:
  virtual ~IReceiverLoop() = default;
  void AddListener(size_t rank, std::shared_ptr<Channel> listener) {
    YACL_ENFORCE(listener != nullptr, "listener is nullptr");

    auto ret = listeners_.emplace(rank, std::move(listener));
    if (!ret.second) {
      YACL_THROW_LOGIC_ERROR("duplicated listener for rank={}", rank);
    }
  }
  //
  virtual void Stop() = 0;

 protected:
  std::map<size_t, std::shared_ptr<Channel>> listeners_;
};

}  // namespace yacl::link::transport
