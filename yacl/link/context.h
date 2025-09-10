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

#include <spdlog/common.h>

#include <atomic>
#include <cstdint>
#include <limits>
#include <map>
#include <string>
#include <vector>

#include "yacl/base/byte_container_view.h"
#include "yacl/link/retry_options.h"
#include "yacl/link/ssl_options.h"
#include "yacl/link/transport/channel.h"
#include "yacl/utils/hash_combine.h"

#include "yacl/link/link.pb.h"

namespace yacl::link {

constexpr size_t kAllRank = std::numeric_limits<size_t>::max();

struct ContextDesc {
  static constexpr char kDefaultId[] = "root";
  static constexpr uint32_t kDefaultConnectRetryTimes = 10;
  static constexpr uint32_t kDefaultConnectRetryIntervalMs = 1000;  // 1 second.
  static constexpr uint64_t kDefaultRecvTimeoutMs = 30 * 1000;      // 30s
  static constexpr uint32_t kDefaultHttpMaxPayloadSize =
      1024 * 1024;                                              //  1M Bytes
  static constexpr uint32_t kDefaultHttpTimeoutMs = 20 * 1000;  // 20 seconds.
  static constexpr uint32_t kDefaultThrottleWindowSize = 10;
  static constexpr uint32_t kDefaultChunkParallelSendSize = 8;
  static constexpr char kDefaultBrpcChannelProtocol[] = "baidu_std";
  static constexpr char kDefaultLinkType[] = "normal";

  struct Party {
    std::string id;
    std::string host;

    bool operator==(const Party& p) const {
      return (id == p.id) && (host == p.host);
    }

    Party() = default;

    Party(const PartyProto& pb) : id(pb.id()), host(pb.host()) {}

    Party(const std::string& id_, const std::string& host_)
        : id(id_), host(host_) {}
  };

  // the UUID of this communication.
  std::string id = kDefaultId;

  // party description, describes the world.
  std::vector<Party> parties;

  // connect to mesh retry time.
  uint32_t connect_retry_times = kDefaultConnectRetryTimes;

  // connect to mesh retry interval.
  uint32_t connect_retry_interval_ms =
      kDefaultConnectRetryIntervalMs;  // 1 second.

  // recv timeout in milliseconds.
  //
  // 'recv time' is the max time that a party will wait for a given event.
  // for example:
  //
  //      begin recv                 end recv
  // |--------|-------recv-time----------|------------------| alice's timeline
  //
  //                         begin send     end send
  // |-----busy-work-------------|-------------|------------| bob's timeline
  //
  // in above case, when alice begins recv for a specific event, bob is still
  // busy doing its job, when alice's wait time exceed wait_timeout_ms, it raise
  // exception, although bob now is starting to send data.
  //
  // so for long time work(that one party may wait for the others for very long
  // time), this value should be changed accordingly.
  uint64_t recv_timeout_ms = kDefaultRecvTimeoutMs;  // 30s

  // http max payload size, if a single http request size is greater than this
  // limit, it will be unpacked into small chunks then reassembled.
  //
  // This field does affect performance. Please choose wisely.
  uint32_t http_max_payload_size = kDefaultHttpMaxPayloadSize;  //  1M Bytes

  // a single http request timetout.
  uint32_t http_timeout_ms = kDefaultHttpTimeoutMs;  // 20 seconds.

  // throttle window size for channel. if there are more than limited size
  // messages are flying, `SendAsync` will block until messages are processed or
  // throw exception after wait for `recv_timeout_ms`
  uint32_t throttle_window_size = kDefaultThrottleWindowSize;

  // chunk parallel send size for channel. if need chunked send when send
  // message, the max paralleled send size is chunk_parallel_send_size
  uint32_t chunk_parallel_send_size = kDefaultChunkParallelSendSize;

  // BRPC client channel protocol.
  std::string brpc_channel_protocol = kDefaultBrpcChannelProtocol;

  // BRPC client channel connection type.
  std::string brpc_channel_connection_type = "";

  // ssl options for link channel
  bool enable_ssl = false;

  // ssl options for link channel
  // this option is ignored if enable_ssl == false;
  SSLOptions client_ssl_opts;

  // ssl options for link service
  // this option is ignored if enable_ssl == false;
  SSLOptions server_ssl_opts;

  // if true, process will exit(-1) when error happened in link async operate
  // otherwise, only log error.
  bool exit_if_async_error = true;

  // "blackbox" or "normal", default: "normal"
  std::string link_type = kDefaultLinkType;

  RetryOptions retry_opts;

  bool disable_msg_seq_id = false;

  bool operator==(const ContextDesc& other) const {
    return (id == other.id) && (parties == other.parties);
  }

  ContextDesc() = default;

  ContextDesc(const ContextDescProto& pb)
      : id(pb.id().size() ? pb.id() : kDefaultId),
        connect_retry_times(pb.connect_retry_times()
                                ? pb.connect_retry_times()
                                : kDefaultConnectRetryTimes),
        connect_retry_interval_ms(pb.connect_retry_interval_ms()
                                      ? pb.connect_retry_interval_ms()
                                      : kDefaultConnectRetryIntervalMs),
        recv_timeout_ms(pb.recv_timeout_ms() ? pb.recv_timeout_ms()
                                             : kDefaultRecvTimeoutMs),
        http_max_payload_size(pb.http_max_payload_size()
                                  ? pb.http_max_payload_size()
                                  : kDefaultHttpMaxPayloadSize),
        http_timeout_ms(pb.http_timeout_ms() ? pb.http_timeout_ms()
                                             : kDefaultHttpTimeoutMs),
        throttle_window_size(pb.throttle_window_size()
                                 ? pb.throttle_window_size()
                                 : kDefaultThrottleWindowSize),
        chunk_parallel_send_size(pb.chunk_parallel_send_size()
                                     ? pb.chunk_parallel_send_size()
                                     : kDefaultChunkParallelSendSize),
        brpc_channel_protocol(pb.brpc_channel_protocol().size()
                                  ? pb.brpc_channel_protocol()
                                  : kDefaultBrpcChannelProtocol),
        brpc_channel_connection_type(pb.brpc_channel_connection_type()),
        enable_ssl(pb.enable_ssl()),
        client_ssl_opts(pb.client_ssl_opts()),
        server_ssl_opts(pb.server_ssl_opts()),
        link_type(kDefaultLinkType),
        retry_opts(pb.retry_opts()) {
    for (const auto& party_pb : pb.parties()) {
      parties.emplace_back(party_pb);
    }
  }
};

struct ContextDescHasher {
  size_t operator()(const ContextDesc& desc) const {
    size_t seed = 0;
    utils::hash_combine(seed, desc.id);

    for (const auto& p : desc.parties) {
      utils::hash_combine(seed, p.id, p.host);
    }

    utils::hash_combine(seed, desc.connect_retry_times,
                        desc.connect_retry_interval_ms, desc.recv_timeout_ms,
                        desc.http_max_payload_size, desc.http_timeout_ms,
                        desc.throttle_window_size, desc.brpc_channel_protocol,
                        desc.brpc_channel_connection_type, desc.link_type);

    return seed;
  }
};

struct Statistics {
  // total number of data sent in bytes, excluding key
  std::atomic<size_t> sent_bytes = 0U;

  // total number of sent actions, chunked mode is treated as a single action.
  std::atomic<size_t> sent_actions = 0U;

  // total number of data received in bytes, excluding key.
  std::atomic<size_t> recv_bytes = 0U;

  // total number of recv actions, chunked mode is treated as a single action.
  std::atomic<size_t> recv_actions = 0U;
};

// Threading: link context could only be used in one thread, since
// communication rounds are identified by (incremental) counters.
//
// Spawn it if you need to use it in a different thread, the
// channels/event_loop will be shared between parent/child contexts.
class Context {
 public:
  Context(ContextDesc desc, size_t rank,
          std::vector<std::shared_ptr<transport::IChannel>> channels,
          std::shared_ptr<transport::IReceiverLoop> msg_loop,
          bool is_sub_world = false);

  Context(const ContextDescProto& desc_pb, size_t rank,
          std::vector<std::shared_ptr<transport::IChannel>> channels,
          std::shared_ptr<transport::IReceiverLoop> msg_loop,
          bool is_sub_world = false);

  std::string Id() const;

  size_t WorldSize() const;

  size_t Rank() const;

  size_t NextRank(size_t stride = 1) const;

  size_t PrevRank(size_t stride = 1) const;

  // P2P algorithms
  void SendAsync(size_t dst_rank, ByteContainerView value,
                 std::string_view tag);

  void SendAsync(size_t dst_rank, Buffer&& value, std::string_view tag);

  void SendAsyncThrottled(size_t dst_rank, ByteContainerView value,
                          std::string_view tag);

  void SendAsyncThrottled(size_t dst_rank, Buffer&& value,
                          std::string_view tag);

  void Send(size_t dst_rank, ByteContainerView value, std::string_view tag);

  Buffer Recv(size_t src_rank, std::string_view tag);

  // Connect to mesh, you can also set the connect log level to any
  // spdlog::level
  void ConnectToMesh(
      spdlog::level::level_enum connect_log_level = spdlog::level::debug);

  std::unique_ptr<Context> Spawn(const std::string& id = "");

  // Create a new Context from a subset of original parities.
  // Party which not in `sub_parties` should not call the SubWorld() method.
  // `id_suffix` will append to original context id as new context id
  std::unique_ptr<Context> SubWorld(
      std::string_view id_suffix,
      const std::vector<std::string>& sub_party_ids);

  void SetRecvTimeout(uint64_t recv_timeout_ms);

  uint64_t GetRecvTimeout() const;

  void WaitLinkTaskFinish();

  void AbortLink();

  void SetThrottleWindowSize(size_t);

  void SetChunkParallelSendSize(size_t);

  // for internal algorithms.
  void SendAsyncInternal(size_t dst_rank, const std::string& key,
                         ByteContainerView value);
  void SendAsyncInternal(size_t dst_rank, const std::string& key,
                         Buffer&& value);

  void SendAsyncThrottledInternal(size_t dst_rank, const std::string& key,
                                  ByteContainerView value);
  void SendAsyncThrottledInternal(size_t dst_rank, const std::string& key,
                                  Buffer&& value);

  void SendInternal(size_t dst_rank, const std::string& key,
                    ByteContainerView value);
  Buffer RecvInternal(size_t src_rank, const std::string& key);

  // next collective algorithm id.
  std::string NextId();

  std::string PartyIdByRank(size_t rank) { return desc_.parties[rank].id; }

  // next P2P comm id.
  std::string NextP2PId(size_t src_rank, size_t dst_rank);

  // for external message loop
  std::shared_ptr<transport::IChannel> GetChannel(size_t src_rank) const;

  // print statistics
  void PrintStats();

  // get statistics
  std::shared_ptr<const Statistics> GetStats() const;

 protected:
  using P2PDirection = std::pair<int, int>;

  const ContextDesc desc_;  // world description.
  const size_t rank_;       // my rank.
  const std::vector<std::shared_ptr<transport::IChannel>> channels_;
  const std::shared_ptr<transport::IReceiverLoop> receiver_loop_;

  // stateful properties.
  size_t counter_ = 0U;  // collective algorithm counter.
  std::map<P2PDirection, int> p2p_counter_;
  size_t child_counter_ = 0U;

  uint64_t recv_timeout_ms_;

  // sub-context will shared statistics with parent
  std::shared_ptr<Statistics> stats_;

  const bool is_sub_world_;
};

// a RecvTimeoutGuard is to help set the recv timeout value for the Context.
// for example:
// {
//  RecvTimeoutGuard guard(ctx, timeout);
//  method();
// }
// in above case, the Context's recv_timeout_ms_ is set to timout before the
// method and recovers to its original value automatically after the
// method finishes.
class RecvTimeoutGuard {
 public:
  // set recv timeout and save original value
  RecvTimeoutGuard(const std::shared_ptr<Context>& ctx,
                   uint64_t recv_timeout_ms)
      : ctx_(ctx), recv_timeout_ms_(ctx->GetRecvTimeout()) {
    ctx->SetRecvTimeout(recv_timeout_ms);
  }
  // recover original timeout value
  ~RecvTimeoutGuard() { ctx_->SetRecvTimeout(recv_timeout_ms_); }

  RecvTimeoutGuard(const RecvTimeoutGuard&) = delete;
  RecvTimeoutGuard& operator=(const RecvTimeoutGuard&) = delete;

 private:
  const std::shared_ptr<Context>& ctx_;
  uint64_t recv_timeout_ms_;
};

}  // namespace yacl::link
