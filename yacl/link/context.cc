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

#include "yacl/link/context.h"

#include <spdlog/common.h>

#include <chrono>
#include <iostream>
#include <thread>

#include "fmt/format.h"
#include "spdlog/spdlog.h"

#include "yacl/base/exception.h"
#include "yacl/link/trace.h"

namespace yacl::link {

#define SPDLOG_COND(LEVEL, ...)  \
  switch (LEVEL) {               \
    case spdlog::level::trace:   \
      SPDLOG_TRACE(__VA_ARGS__); \
      break;                     \
    case spdlog::level::debug:   \
      SPDLOG_DEBUG(__VA_ARGS__); \
      break;                     \
    case spdlog::level::info:    \
      SPDLOG_INFO(__VA_ARGS__);  \
      break;                     \
    case spdlog::level::warn:    \
      SPDLOG_WARN(__VA_ARGS__);  \
      break;                     \
    case spdlog::level::err:     \
      SPDLOG_ERROR(__VA_ARGS__); \
      break;                     \
    default:                     \
      SPDLOG_DEBUG(__VA_ARGS__); \
      break;                     \
  }

std::ostream& operator<<(std::ostream& os, const Statistics& st) {
  os << "sent_bytes=" << st.sent_bytes       //
     << ",sent_actions=" << st.sent_actions  //
     << ",recv_bytes=" << st.recv_bytes      //
     << ",recv_actions=" << st.recv_actions << std::endl;
  return os;
}

void Context::PrintStats() { std::cout << *stats_; }

std::shared_ptr<const Statistics> Context::GetStats() const { return stats_; }

Context::Context(ContextDesc desc, size_t rank,
                 std::vector<std::shared_ptr<transport::IChannel>> channels,
                 std::shared_ptr<transport::IReceiverLoop> msg_loop,
                 bool is_sub_world)
    : desc_(std::move(desc)),
      rank_(rank),
      channels_(std::move(channels)),
      receiver_loop_(std::move(msg_loop)),
      recv_timeout_ms_(desc_.recv_timeout_ms),
      is_sub_world_(is_sub_world) {
  const size_t world_size = desc_.parties.size();

  YACL_ENFORCE(rank_ < static_cast<size_t>(world_size),
               "rank={} out of range world_size={}", rank, world_size);
  YACL_ENFORCE(channels_.size() == world_size,
               "channels lenth={} does not match world_size={}",
               channels_.size(), world_size);

  for (size_t src = 0; src < world_size; ++src) {
    for (size_t dst = 0; dst < world_size; ++dst) {
      p2p_counter_[std::make_pair(src, dst)] = 0U;
    }
  }

  stats_ = std::make_shared<Statistics>();
}

Context::Context(const ContextDescProto& desc_pb, size_t rank,
                 std::vector<std::shared_ptr<transport::IChannel>> channels,
                 std::shared_ptr<transport::IReceiverLoop> msg_loop,
                 bool is_sub_world)
    : Context(ContextDesc(), rank, channels, msg_loop, is_sub_world) {}

std::string Context::Id() const { return desc_.id; }

size_t Context::WorldSize() const { return desc_.parties.size(); }

size_t Context::Rank() const { return rank_; }

size_t Context::PrevRank(size_t stride) const {
  return (rank_ - stride + WorldSize()) % WorldSize();
}

size_t Context::NextRank(size_t stride) const {
  return (rank_ + stride) % WorldSize();
}

void Context::SetThrottleWindowSize(size_t w) {
  for (const auto& l : channels_) {
    if (l) {
      l->SetThrottleWindowSize(w);
    }
  }
}

void Context::WaitLinkTaskFinish() {
  YACL_ENFORCE(is_sub_world_ == false,
               "DO NOT call WaitLinkTaskFinish on sub world link");
  for (const auto& l : channels_) {
    if (l) {
      l->WaitLinkTaskFinish();
    }
  }
}

void Context::ConnectToMesh(spdlog::level::level_enum connect_log_level) {
  SPDLOG_COND(connect_log_level, "connecting to mesh, id={}, self={}", Id(),
              Rank());

  auto try_connect = [&](size_t rank, uint32_t timeout) {
    try {
      SPDLOG_COND(connect_log_level, "attempt to connect to rank={}", rank);
      channels_[rank]->TestSend(timeout);
    } catch (const NetworkError& e) {
      SPDLOG_COND(connect_log_level,
                  "try connect to rank={} failed with error {}", rank,
                  e.what());
      return false;
    }
    return true;
  };

  // broadcast to all
  for (size_t idx = 0; idx < WorldSize(); idx++) {
    if (idx == Rank()) {
      continue;
    }
    bool succeed = false;
    const uint32_t send_attempt = desc_.connect_retry_times;
    const uint32_t http_timeout_ms_base = 1000;
    for (uint32_t attempt = 0; attempt < send_attempt; attempt++) {
      if (attempt != 0) {
        // sleep and retry.
        SPDLOG_COND(
            connect_log_level,
            "try_connect to rank {} not succeed, sleep_for {}ms and retry.",
            idx, desc_.connect_retry_interval_ms);

        std::this_thread::sleep_for(
            std::chrono::milliseconds(desc_.connect_retry_interval_ms));
      }
      // Cyclically trying [2, 12]s *http* timeout
      if (try_connect(idx, ((attempt % 11) + 2) * http_timeout_ms_base)) {
        succeed = true;
        break;
      }
    }

    if (!succeed) {
      YACL_THROW(
          "connect to mesh failed, failed to setup connection to rank={}", idx);
    }
  }
  SPDLOG_COND(connect_log_level, "connecting to mesh, all partners launched");

  // gather all
  for (size_t idx = 0; idx < WorldSize(); idx++) {
    if (idx == Rank()) {
      continue;
    }
    channels_[idx]->TestRecv();
  }

  SPDLOG_COND(connect_log_level, "connected to mesh, id={}, self={}", Id(),
              Rank());
}

// P2P algorithms
void Context::SendAsync(size_t dst_rank, ByteContainerView value,
                        std::string_view tag) {
  const auto event = NextP2PId(rank_, dst_rank);

  TraceLogger::LinkTrace(event, tag, value);

  SendAsyncInternal(dst_rank, event, value);
}

void Context::SendAsync(size_t dst_rank, Buffer&& value, std::string_view tag) {
  const auto event = NextP2PId(rank_, dst_rank);

  TraceLogger::LinkTrace(event, tag, value);

  SendAsyncInternal(dst_rank, event, std::move(value));
}

void Context::SendAsyncThrottled(size_t dst_rank, ByteContainerView value,
                                 std::string_view tag) {
  const auto event = NextP2PId(rank_, dst_rank);

  TraceLogger::LinkTrace(event, tag, value);

  SendAsyncThrottledInternal(dst_rank, event, value);
}

void Context::SendAsyncThrottled(size_t dst_rank, Buffer&& value,
                                 std::string_view tag) {
  const auto event = NextP2PId(rank_, dst_rank);

  TraceLogger::LinkTrace(event, tag, value);

  SendAsyncThrottledInternal(dst_rank, event, std::move(value));
}

void Context::Send(size_t dst_rank, ByteContainerView value,
                   std::string_view tag) {
  const auto event = NextP2PId(rank_, dst_rank);

  TraceLogger::LinkTrace(event, tag, value);

  SendInternal(dst_rank, event, value);
}

Buffer Context::Recv(size_t src_rank, std::string_view tag) {
  const auto event = NextP2PId(src_rank, rank_);

  TraceLogger::LinkTrace(event, tag, "");

  return RecvInternal(src_rank, event);
}

void Context::SendAsyncInternal(size_t dst_rank, const std::string& key,
                                ByteContainerView value) {
  YACL_ENFORCE(dst_rank < static_cast<size_t>(channels_.size()),
               "rank={} out of range={}", dst_rank, channels_.size());

  channels_[dst_rank]->SendAsync(key, value);

  stats_->sent_actions++;
  stats_->sent_bytes += value.size();
}

void Context::SendAsyncInternal(size_t dst_rank, const std::string& key,
                                Buffer&& value) {
  YACL_ENFORCE(dst_rank < channels_.size(), "rank={} out of range={}", dst_rank,
               channels_.size());

  const size_t value_length = value.size();

  channels_[dst_rank]->SendAsync(key, std::move(value));

  stats_->sent_actions++;
  stats_->sent_bytes += value_length;
}

void Context::SendAsyncThrottledInternal(size_t dst_rank,
                                         const std::string& key,
                                         ByteContainerView value) {
  YACL_ENFORCE(dst_rank < static_cast<size_t>(channels_.size()),
               "rank={} out of range={}", dst_rank, channels_.size());

  channels_[dst_rank]->SendAsyncThrottled(key, value);

  stats_->sent_actions++;
  stats_->sent_bytes += value.size();
}

void Context::SendAsyncThrottledInternal(size_t dst_rank,
                                         const std::string& key,
                                         Buffer&& value) {
  YACL_ENFORCE(dst_rank < channels_.size(), "rank={} out of range={}", dst_rank,
               channels_.size());

  const size_t value_length = value.size();

  channels_[dst_rank]->SendAsyncThrottled(key, std::move(value));

  stats_->sent_actions++;
  stats_->sent_bytes += value_length;
}

void Context::SendInternal(size_t dst_rank, const std::string& key,
                           ByteContainerView value) {
  YACL_ENFORCE(dst_rank < static_cast<size_t>(channels_.size()),
               "rank={} out of range={}", dst_rank, channels_.size());

  channels_[dst_rank]->Send(key, value);

  stats_->sent_actions++;
  stats_->sent_bytes += value.size();
}

Buffer Context::RecvInternal(size_t src_rank, const std::string& key) {
  YACL_ENFORCE(src_rank < static_cast<size_t>(channels_.size()),
               "rank={} out of range={}", src_rank, channels_.size());

  auto value = channels_[src_rank]->Recv(key);

  stats_->recv_actions++;
  stats_->recv_bytes += value.size();

  return value;
}

std::unique_ptr<Context> Context::Spawn() {
  ContextDesc sub_desc = desc_;
  sub_desc.id = fmt::format("{}-{}", desc_.id, child_counter_++);

  // sub-context share the same event-loop and statistics with parent.
  auto sub_ctx =
      std::make_unique<Context>(sub_desc, rank_, channels_, receiver_loop_);

  // share statistics with parent.
  sub_ctx->stats_ = this->stats_;

  return sub_ctx;
}

std::unique_ptr<Context> Context::SubWorld(
    std::string_view id_suffix, const std::vector<std::string>& sub_party_ids) {
  size_t new_rank = sub_party_ids.size();
  std::vector<size_t> orig_ranks;
  {
    std::map<std::string, size_t> party_rank_map;

    for (size_t i = 0; i < desc_.parties.size(); i++) {
      party_rank_map[desc_.parties[i].id] = i;
    }

    for (const auto& party_id : sub_party_ids) {
      auto iter = party_rank_map.find(party_id);
      YACL_ENFORCE(iter != party_rank_map.end(),
                   "original context does not contain party={}", party_id);
      if (iter->second == Rank()) {
        new_rank = orig_ranks.size();
      }
      orig_ranks.push_back(iter->second);
    }
  }

  if (new_rank == sub_party_ids.size()) {
    YACL_THROW("Context::SubWorld parties must contain self-party");
  }

  ContextDesc sub_desc = desc_;
  {
    sub_desc.id = fmt::format("{}-{}", desc_.id, id_suffix);
    sub_desc.parties.resize(sub_party_ids.size());
    for (size_t i = 0; i < sub_party_ids.size(); i++) {
      sub_desc.parties[i] = desc_.parties[orig_ranks[i]];
    }
  }

  std::vector<std::shared_ptr<transport::IChannel>> channels(
      sub_party_ids.size());
  for (size_t i = 0; i < sub_party_ids.size(); i++) {
    channels[i] = channels_[orig_ranks[i]];
  }

  // sub-world context share the same channel & event-loop with parent.
  return std::make_unique<Context>(sub_desc, new_rank, channels, receiver_loop_,
                                   true);
}

std::string Context::NextId() {
  return fmt::format("{}:{}", desc_.id, ++counter_);
}

std::string Context::NextP2PId(size_t src_rank, size_t dst_rank) {
  return fmt::format("{}:P2P-{}:{}->{}", desc_.id,
                     ++p2p_counter_[std::make_pair(src_rank, dst_rank)],
                     src_rank, dst_rank);
}

std::shared_ptr<transport::IChannel> Context::GetChannel(
    size_t src_rank) const {
  YACL_ENFORCE(src_rank < WorldSize(), "unexpected rank={} with world_size={}",
               src_rank, WorldSize());
  return channels_[src_rank];
}

void Context::SetRecvTimeout(uint64_t recv_timeout_ms) {
  recv_timeout_ms_ = recv_timeout_ms;
  for (size_t idx = 0; idx < WorldSize(); idx++) {
    if (idx == Rank()) {
      continue;
    }
    channels_[idx]->SetRecvTimeout(recv_timeout_ms_);
  }
  SPDLOG_DEBUG("set recv timeout, timeout_ms={}", recv_timeout_ms_);
}

uint64_t Context::GetRecvTimeout() const { return recv_timeout_ms_; }

#undef SPDLOG_COND

}  // namespace yacl::link
