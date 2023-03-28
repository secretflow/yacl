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
#include <string>

#include "bthread/bthread.h"
#include "bthread/condition_variable.h"

#include "yacl/base/buffer.h"
#include "yacl/base/byte_container_view.h"
#include "yacl/utils/segment_tree.h"

namespace yacl::link {

// A channel is basic interface for p2p communicator.
class IChannel {
 public:
  virtual ~IChannel() = default;

  // SendAsync asynchronously.
  // return when the message successfully pushed into peer's recv buffer.
  // SendAsync is not reentrant with same key.
  virtual void SendAsync(const std::string& key, ByteContainerView value) = 0;

  virtual void SendAsync(const std::string& key, Buffer&& value) = 0;

  // SendAsync synchronously.
  // return when the message is successfully pushed into the send buffer.
  // raise when push buffer overflow.
  // Send is not reentrant with same key.
  virtual void Send(const std::string& key, ByteContainerView value) = 0;

  // block waiting message.
  virtual Buffer Recv(const std::string& key) = 0;

  // called by an async dispatcher.
  virtual void OnMessage(const std::string& key, ByteContainerView value) = 0;

  // called by an async dispatcher.
  virtual void OnChunkedMessage(const std::string& key, ByteContainerView value,
                                size_t offset, size_t total_length) = 0;
  // set receive timeout ms
  virtual void SetRecvTimeout(uint32_t timeout_ms) = 0;

  // get receive timemout ms
  virtual uint32_t GetRecvTimeout() const = 0;

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

class ChannelBase : public IChannel {
 public:
  ChannelBase(size_t self_rank, size_t peer_rank)
      : self_rank_(self_rank), peer_rank_(peer_rank) {}

  ChannelBase(size_t self_rank, size_t peer_rank, size_t recv_timeout_ms)
      : self_rank_(self_rank),
        peer_rank_(peer_rank),
        recv_timeout_ms_(recv_timeout_ms) {}

  // all send interface for normal msg is not reentrant with same key.
  void SendAsync(const std::string& key, ByteContainerView value) final;

  void SendAsync(const std::string& key, Buffer&& value) final;

  void Send(const std::string& key, ByteContainerView value) final;

  Buffer Recv(const std::string& key) override;

  void OnMessage(const std::string& key, ByteContainerView value) override;

  void OnChunkedMessage(const std::string& key, ByteContainerView value,
                        size_t offset, size_t total_length) override;

  void SetRecvTimeout(uint32_t recv_timeout_ms) override;

  uint32_t GetRecvTimeout() const override;

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

  // wait for all SendAsync Done.
  virtual void WaitAsyncSendToFinish() = 0;

 protected:
  virtual void SendAsyncImpl(const std::string& key,
                             ByteContainerView value) = 0;

  virtual void SendAsyncImpl(const std::string& key, Buffer&& value) = 0;

  virtual void SendImpl(const std::string& key, ByteContainerView value) = 0;

  virtual void SendImpl(const std::string& key, ByteContainerView value,
                        uint32_t timeout) = 0;

 private:
  void ThrottleWindowWait(size_t);

  void StopReceivingAndAckUnreadMsgs();

  void WaitForFinAndFlyingMsg();

  void WaitForFlyingAck();

  template <typename T>
  void OnNormalMessage(const std::string&, T&&);

  void SendAck(size_t seq_id);

 protected:
  const size_t self_rank_;
  const size_t peer_rank_;

  uint32_t recv_timeout_ms_ = 3 * 60 * 1000;  // 3 minites

  // message database related.
  bthread::Mutex msg_mutex_;
  bthread::ConditionVariable msg_db_cond_;
  // msg_key -> <value, seq_id>
  std::map<std::string, std::pair<Buffer, size_t>> msg_db_;

  // for Throttle Window
  std::atomic<size_t> throttle_window_size_ = 0;
  size_t ack_msg_count_ = 0;

  // for WaitLinkTaskFinish
  // if WaitLinkTaskFinish is called.
  // auto ack all normal msg if true.
  std::atomic<bool> waiting_finish_ = false;
  // id count for normal msg sent to peer.
  std::atomic<size_t> sent_msg_seq_id_ = 0;
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

  // chunking related.
  bthread::Mutex chunked_values_mutex_;
  std::map<std::string, std::shared_ptr<ChunkedMessage>> chunked_values_;
};

// A receiver loop is a thread loop which receives messages from the world.
// It listens message from all over the world and delivers to listeners.
class IReceiverLoop {
 public:
  virtual ~IReceiverLoop() = default;

  //
  virtual void Stop() = 0;

  // add listener who interested messages from 'rank'
  virtual void AddListener(size_t rank, std::shared_ptr<IChannel> channel) = 0;
};

class ReceiverLoopBase : public IReceiverLoop {
 public:
  void AddListener(size_t rank, std::shared_ptr<IChannel> listener) override;

 protected:
  std::map<size_t, std::shared_ptr<IChannel>> listeners_;
};

}  // namespace yacl::link
