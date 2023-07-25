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

#include "bthread/bthread.h"
#include "bthread/condition_variable.h"
#include "spdlog/spdlog.h"

#include "yacl/base/buffer.h"
#include "yacl/base/byte_container_view.h"
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

  // set send throttle window size
  virtual void SetThrottleWindowSize(size_t) = 0;

  // test if this channel can send a dummy msg to peer.
  // use fixed 0 seq_id as dummy msg's id make this function reentrant.
  // because ConnectToMesh will retry on this multiple times.
  virtual void TestSend(uint32_t timeout) = 0;

  // wait for dummy msg from peer, timeout by recv_timeout_ms_.
  virtual void TestRecv() = 0;
};

// forward declaractions.
class ChunkedMessage;

class ChannelBase : public IChannel,
                    public std::enable_shared_from_this<ChannelBase> {
 public:
  ChannelBase(size_t self_rank, size_t peer_rank, bool exit_if_async_error)
      : self_rank_(self_rank),
        peer_rank_(peer_rank),
        exit_if_async_error_(exit_if_async_error) {
    StartSendThread();
  }

  ChannelBase(size_t self_rank, size_t peer_rank, size_t recv_timeout_ms,
              bool exit_if_async_error)
      : self_rank_(self_rank),
        peer_rank_(peer_rank),
        recv_timeout_ms_(recv_timeout_ms),
        exit_if_async_error_(exit_if_async_error) {
    StartSendThread();
  }

  ~ChannelBase() override {
    if (!send_thread_stoped_.load()) {
      SPDLOG_WARN(
          "ChannelBase destructor is called before WaitLinkTaskFinish, try "
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

  void SetThrottleWindowSize(size_t size) final {
    throttle_window_size_ = size;
  }

  // test if this channel can send a dummy msg to peer.
  // use 0 seq_id as dummy msg's id.
  // Reentrancy function for ConnectToMesh test.
  void TestSend(uint32_t timeout) final;

  // wait for dummy msg from peer, timeout by recv_timeout_ms_.
  void TestRecv() final;

 protected:
  virtual void SendImpl(const std::string& key, ByteContainerView value) = 0;

  virtual void SendImpl(const std::string& key, ByteContainerView value,
                        uint32_t timeout_override_ms) = 0;

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

   private:
    bthread::Mutex mutex_;
    size_t running_tasks_ = 0;
    utils::SegmentTree<size_t> finished_ids_;
    bthread::ConditionVariable finished_cond_;
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
  };

 protected:
  const size_t self_rank_;
  const size_t peer_rank_;

  uint64_t recv_timeout_ms_ = 3UL * 60 * 1000;  // 3 minites

  MessageQueue msg_queue_;
  std::thread send_thread_;
  std::atomic<bool> send_thread_stoped_ = false;
  SendTaskSynchronizer send_sync_;

  // message database related.
  bthread::Mutex msg_mutex_;
  bthread::ConditionVariable msg_db_cond_;
  // msg_key -> <value, seq_id>
  std::map<std::string, std::pair<Buffer, size_t>> msg_db_;

  // for Throttle Window
  std::atomic<size_t> throttle_window_size_ = 0;
  // for WaitLinkTaskFinish
  // if WaitLinkTaskFinish is called.
  // auto ack all normal msg if true.
  std::atomic<bool> waiting_finish_ = false;
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
};

// A receiver loop is a thread loop which receives messages from the world.
// It listens message from all over the world and delivers to listeners.
class IReceiverLoop {
 public:
  virtual ~IReceiverLoop() = default;

  //
  virtual void Stop() = 0;
};

}  // namespace yacl::link::transport
