// Copyright 2024 Ant Group Co., Ltd.
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

#include <future>
#include <iterator>

#include "gflags/gflags.h"
#include "psi/cpp/ecdh_psi.h"
#include "psi/cpp/main_utils.h"

#include "yacl/link/context.h"
#include "yacl/utils/serialize.h"

DEFINE_int32(rank, -1, "rank of the party: 0/1");
DEFINE_string(path, "", "path to the input csv file");

// Declare alias
namespace yc = yacl::crypto;
using LCTX = std::unique_ptr<yacl::link::Context>;

std::vector<uint128_t> ProcessPeerData(const LCTX& lctx,
                                       const examples::psi::EcdhPsi& protocol,
                                       size_t peer_size) {
  std::vector<yc::EcPoint> peer_points(peer_size);
  std::vector<uint128_t> peer_final(peer_size);

  // Receiving all peer's data
  size_t recv_count = 0;
  while (recv_count < peer_size) {
    auto buf = lctx->Recv(
        lctx->NextRank(),
        fmt::format("[{}]: Recving peer masked values", lctx->Rank()));
    peer_points[recv_count] = protocol.GetGroup()->DeserializePoint(buf);
    recv_count++;
  }

  YACL_ENFORCE_EQ(recv_count, peer_size);

  // Mask all peer's points
  protocol.MaskEcPointsAndHashToU128(absl::MakeSpan(peer_points),
                                     absl::MakeSpan(peer_final));

  // Send back all informations
  for (const auto& u128 : peer_final) {
    lctx->Send(
        lctx->NextRank(), yacl::SerializeUint128(u128),
        fmt::format("[{}]: Sending peer double-masked values", lctx->Rank()));
  }

  return peer_final;
}

std::vector<uint128_t> ProcessSelfData(const LCTX& lctx,
                                       const examples::psi::EcdhPsi& protocol,
                                       absl::Span<std::string> self_data) {
  size_t self_size = self_data.size();
  std::vector<yc::EcPoint> self_points(self_size);
  std::vector<uint128_t> self_final(self_size);

  // Mask self data
  protocol.MaskStrings(absl::MakeSpan(self_data), absl::MakeSpan(self_points));

  // Send masked self data
  for (const auto& point : self_points) {
    lctx->Send(lctx->NextRank(), protocol.GetGroup()->SerializePoint(point),
               fmt::format("[{}]: Sending self masked values", lctx->Rank()));
  }

  // Receiving double-masked self-data
  size_t recv_count = 0;
  while (recv_count < self_size) {
    auto buf = lctx->Recv(
        lctx->NextRank(),
        fmt::format("[{}]: Recving peer masked values", lctx->Rank()));
    self_final[recv_count] = yacl::DeserializeUint128(buf);
    recv_count++;
  }
  YACL_ENFORCE_EQ(recv_count, self_size);

  return self_final;
}

void StartPsi(int rank, const std::string& file_path) {
  YACL_ENFORCE(rank == 0 || rank == 1, "Invalid Arguemnts: rank");
  YACL_ENFORCE(!file_path.empty());
  auto data_str = LoadCsv(file_path);

  // NOTE link::Context is not thread-safe
  auto lctx = SetupLink(rank);
  auto self_lctx = lctx->Spawn(fmt::format("{}", lctx->Rank()));
  auto peer_lctx = lctx->Spawn(fmt::format("{}", lctx->NextRank()));
  SPDLOG_INFO("Phase 0: Setup network, data, and everything else ... done");

  // Phase 0.5: Exchange metadata
  SPDLOG_INFO("Phase 0.5: Exchange metadata ... ");
  lctx->SendAsync(lctx->NextRank(), yacl::SerializeUint128(data_str.size()),
                  fmt::format("[{}]: Data num = {}", rank, data_str.size()));

  auto peer_size = yacl::DeserializeInt128(
      lctx->Recv(lctx->NextRank(),
                 fmt::format("[{}]: Data num = {}", rank, data_str.size())));
  SPDLOG_INFO("Phase 0.5: Exchange metadata ... done, got self={}, peer={}",
              data_str.size(), peer_size);

  // Phase 1: Init protocol and start self and peer process (async)
  SPDLOG_INFO("Phase 1: Init protocol and start peer process (async) ...");
  examples::psi::EcdhPsi protocol;

  auto peer_data_process = std::async(
      [&]() { return ProcessPeerData(peer_lctx, protocol, peer_size); });

  auto self_final =
      ProcessSelfData(self_lctx, protocol, absl::MakeSpan(data_str));

  auto peer_final = peer_data_process.get();

  SPDLOG_INFO(
      "Phase 1: Init protocol and start peer process (async) ... "
      "done");

  // Phase 2: Final comparison
  SPDLOG_INFO("Phase 2: Trying to calculate the intersection locally ... ");
  std::vector<uint128_t> out;
  std::set_intersection(self_final.begin(), self_final.end(),
                        peer_final.begin(), peer_final.end(),
                        std::back_inserter(out));
  SPDLOG_INFO(
      "Phase 2: Trying to calculate the intersection locally ... done, got "
      "intersection size = {}",
      out.size());

  lctx->WaitLinkTaskFinish();

  SPDLOG_INFO("ECDH-PSI finished");
}

int main(int argc, char* argv[]) {
  google::ParseCommandLineFlags(&argc, &argv, true);

  // Phase 0: Setup network, data, and everything else
  SPDLOG_INFO("Phase 0: Setup network, data, and everything else ...");
  YACL_ENFORCE(FLAGS_rank == 0 || FLAGS_rank == 1, "Invalid Arguemnts: rank");

  std::string file_path =
      FLAGS_path.empty() ? fmt::format("{}/examples/psi/data_{}.csv",
                                       std::filesystem::current_path().string(),
                                       FLAGS_rank == 0 ? "a" : "b")
                         : FLAGS_path;
  StartPsi(FLAGS_rank, file_path);

  return 0;
}
