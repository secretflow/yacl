// Copyright 2024 zhangwfjh
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

#include "yacl/crypto/primitives/psu/krtw19_psu.h"

#include <algorithm>
#include <array>
#include <iterator>
#include <unordered_set>
#include <utility>

#include "yacl/utils/serialize.h"

namespace yacl::crypto {

namespace {

// reference: https://eprint.iacr.org/2019/1234.pdf (Figure 2)
constexpr float kZeta{0.06f};
constexpr size_t kBinSize{64ul};  // m+1
constexpr uint128_t kBot{};
constexpr size_t kNumBinsPerBatch{16ul};
constexpr size_t kBatchSize{kNumBinsPerBatch * kBinSize};

constexpr size_t kNumBaseOT{128ul};
constexpr size_t kNumInkpOT{512ul};

static auto HashToSizeT = [](const uint128_t& x) {
  auto hash = Blake3_128({&x, sizeof x});
  size_t ret;
  std::memcpy(&ret, &hash, sizeof ret);
  return ret;
};

auto HashInputs(const std::vector<uint128_t>& elem_hashes, size_t count) {
  size_t num_bins = std::ceil(count * kZeta);
  std::vector<std::vector<uint128_t>> hashing(num_bins);
  for (auto elem : elem_hashes) {
    auto hash = HashToSizeT(elem);
    hashing[hash % num_bins].emplace_back(elem);
  }
  return hashing;
}

uint64_t Evaluate(const std::vector<uint64_t>& coeffs, uint64_t x) {
  uint64_t y{coeffs.back()};
  for (auto it = std::next(coeffs.rbegin()); it != coeffs.rend(); ++it) {
    y = GfMul64(y, x) ^ *it;
  }
  return y;
}

auto Interpolate(const std::vector<uint64_t>& xs,
                 const std::vector<uint64_t>& ys) {
  YACL_ENFORCE_EQ(xs.size(), ys.size(), "Sizes mismatch.");
  size_t size{xs.size()};
  std::vector<uint64_t> L_coeffs(size);
  for (size_t i{}; i != size; ++i) {
    std::vector<uint64_t> Li_coeffs(size);
    Li_coeffs[0] = ys[i];
    uint64_t prod{1};
    for (size_t j{}; j != size; ++j) {
      if (xs[i] != xs[j]) {
        prod = GfMul64(prod, xs[i] ^ xs[j]);
        uint64_t sum{};
        for (size_t k{}; k != size; ++k) {
          sum = std::exchange(Li_coeffs[k], GfMul64(Li_coeffs[k], xs[j]) ^ sum);
        }
      }
    }
    for (size_t k{}; k != size; ++k) {
      L_coeffs[k] ^= GfMul64(Li_coeffs[k], Inv64(prod));
    }
  }
  return L_coeffs;
}

}  // namespace

void KrtwPsuSend(const std::shared_ptr<yacl::link::Context>& ctx,
                 const std::vector<uint128_t>& elem_hashes) {
  ctx->SendAsync(ctx->NextRank(), SerializeUint128(elem_hashes.size()),
                 "Send set size");
  size_t peer_count =
      DeserializeUint128(ctx->Recv(ctx->PrevRank(), "Receive set size"));
  auto count = std::max(elem_hashes.size(), peer_count);
  if (count == 0) {
    return;
  }
  // Step 1. Hashes inputs
  auto hashing = HashInputs(elem_hashes, count);

  // Step 2. Prepares OPRF
  KkrtOtExtReceiver receiver;
  size_t num_ot{hashing.size() * kBinSize};
  auto choice = RandBits(kNumBaseOT);
  auto base_ot = BaseOtRecv(ctx, choice, kNumBaseOT);
  auto store = IknpOtExtSend(ctx, base_ot, kNumInkpOT);
  receiver.Init(ctx, store, num_ot);
  receiver.SetBatchSize(kBatchSize);

  std::vector<uint128_t> elems;
  elems.reserve(num_ot);
  size_t oprf_idx{};
  for (size_t bin_idx{}; bin_idx != hashing.size(); ++bin_idx) {
    if (bin_idx % kNumBinsPerBatch == 0) {
      receiver.SendCorrection(
          ctx, std::min(kBatchSize, (hashing.size() - bin_idx) * kBinSize));
    }
    hashing[bin_idx].resize(kBinSize);
    std::sort(hashing[bin_idx].begin(), hashing[bin_idx].end());
    // Step 3. For each bin element, invokes PSU(1, m+1)
    for (auto elem : hashing[bin_idx]) {
      elems.emplace_back(elem);
      uint64_t eval;
      receiver.Encode(oprf_idx++, elem,
                      {reinterpret_cast<uint8_t*>(&eval), sizeof eval});
      std::vector<uint64_t> coeffs(kBinSize);
      auto buf = ctx->Recv(ctx->PrevRank(), "Receive coefficients");
      std::memcpy(coeffs.data(), buf.data(), buf.size());
      auto y = Evaluate(coeffs, HashToSizeT(elem)) ^ eval;
      ctx->SendAsync(ctx->NextRank(), SerializeUint128(y), "Send evaluation");
    }
  }

  // Step 4. Sends new elements through OT
  std::vector<std::array<uint128_t, 2>> keys(num_ot);
  choice = SecureRandBits(kNumBaseOT);
  base_ot = BaseOtRecv(ctx, choice, kNumBaseOT);
  IknpOtExtSend(ctx, base_ot, absl::MakeSpan(keys));
  std::vector<uint128_t> ciphers(num_ot);
  for (size_t i{}; i != num_ot; ++i) {
    ciphers[i] = elems[i] ^ keys[i][0];
  }
  ctx->SendAsync(ctx->NextRank(),
                 yacl::Buffer{reinterpret_cast<uint8_t*>(ciphers.data()),
                              ciphers.size() * sizeof(uint128_t)},
                 "Send ciphertexts");
}

std::vector<uint128_t> KrtwPsuRecv(
    const std::shared_ptr<yacl::link::Context>& ctx,
    const std::vector<uint128_t>& elem_hashes) {
  size_t peer_count =
      DeserializeUint128(ctx->Recv(ctx->PrevRank(), "Receive set size"));
  ctx->SendAsync(ctx->NextRank(), SerializeUint128(elem_hashes.size()),
                 "Send set size");
  auto count = std::max(elem_hashes.size(), peer_count);
  if (count == 0) {
    return {};
  }
  // Step 1. Hashes inputs
  auto hashing = HashInputs(elem_hashes, count);

  // Step 2. Prepares OPRF
  KkrtOtExtSender sender;
  size_t num_ot{hashing.size() * kBinSize};
  auto base_ot = BaseOtSend(ctx, kNumBaseOT);
  auto choice = RandBits(kNumInkpOT);
  auto store = IknpOtExtRecv(ctx, base_ot, choice, kNumInkpOT);
  sender.Init(ctx, store, num_ot);
  sender.SetBatchSize(kBatchSize);
  auto oprf = sender.GetOprf();

  yacl::dynamic_bitset<> ot_choice(num_ot);
  size_t oprf_idx{};
  // Step 3. For each bin, invokes PSU(1, m+1)
  for (size_t bin_idx{}; bin_idx != hashing.size(); ++bin_idx) {
    if (bin_idx % kNumBinsPerBatch == 0) {
      sender.RecvCorrection(
          ctx, std::min(kBatchSize, (hashing.size() - bin_idx) * kBinSize));
    }
    auto bin_size = hashing[bin_idx].size();
    for (size_t elem_idx{}; elem_idx != kBinSize; ++elem_idx, ++oprf_idx) {
      auto seed = FastRandU64();
      std::vector<uint64_t> xs(kBinSize), ys(kBinSize);
      for (size_t i{}; i != kBinSize; ++i) {
        xs[i] = (i < bin_size   ? HashToSizeT(hashing[bin_idx][i])
                 : i > bin_size ? FastRandU64()
                                : kBot);
        ys[i] = oprf->Eval(oprf_idx, xs[i]) ^ seed;
      }
      auto coeffs = Interpolate(xs, ys);
      yacl::Buffer buf(coeffs.data(), coeffs.size() * sizeof(uint64_t));
      ctx->SendAsync(ctx->NextRank(), buf, "Send coefficients");
      auto eval =
          DeserializeUint128(ctx->Recv(ctx->PrevRank(), "Receive evaluation"));
      ot_choice[oprf_idx] = eval == seed;
    }
  }

  // Step 4. Receives new elements through OT
  std::vector<uint128_t> keys(num_ot);
  base_ot = BaseOtSend(ctx, kNumBaseOT);
  IknpOtExtRecv(ctx, base_ot, ot_choice, absl::MakeSpan(keys));
  std::vector<uint128_t> ciphers(num_ot);
  auto buf = ctx->Recv(ctx->PrevRank(), "Receive ciphertexts");
  std::memcpy(ciphers.data(), buf.data(), buf.size());
  std::unordered_set<uint128_t, decltype(HashToSizeT)> set_union(
      elem_hashes.begin(), elem_hashes.end(), count, HashToSizeT);
  for (size_t i{}; i != num_ot; ++i) {
    if (!ot_choice[i]) {
      if (auto new_elem = ciphers[i] ^ keys[i]; new_elem != kBot) {
        set_union.emplace(ciphers[i] ^ keys[i]);
      }
    }
  }
  return std::vector(set_union.begin(), set_union.end());
}

}  // namespace yacl::crypto
