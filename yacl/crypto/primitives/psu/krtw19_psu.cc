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
#include <random>

#include "yacl/crypto/base/hash/hash_utils.h"
#include "yacl/crypto/primitives/ot/base_ot.h"
#include "yacl/crypto/primitives/ot/iknp_ote.h"
#include "yacl/crypto/primitives/ot/kkrt_ote.h"
#include "yacl/crypto/utils/rand.h"
#include "yacl/math/gadget.h"
#include "yacl/utils/serialize.h"

namespace yacl::crypto::psu {

namespace yc = yacl::crypto;

namespace {

// reference: https://eprint.iacr.org/2019/1234.pdf (Figure 2)
constexpr float ZETA{0.06f};
constexpr size_t BIN_SIZE{64ul};  // m+1
constexpr uint128_t BOT{};
constexpr size_t NUM_BIN_PER_BATCH{16ul};
constexpr size_t BATCH_SIZE{NUM_BIN_PER_BATCH * BIN_SIZE};

constexpr size_t NUM_BASE_OT{128ul};
constexpr size_t NUM_INKP_OT{512ul};

static std::random_device rd;
static std::mt19937 gen(rd());

struct HashU128 {
  size_t operator()(const uint128_t& x) const {
    return yacl::math::UniversalHash<uint128_t>(1, {x});
  }
};

yacl::Buffer Serialize(uint64_t num) {
  yacl::Buffer buf(sizeof(uint64_t));
  std::memcpy(buf.data(), &num, sizeof(uint64_t));
  return buf;
}

uint64_t Deserialize(const yacl::Buffer& buf) {
  uint64_t num;
  std::memcpy(&num, buf.data(), sizeof(uint64_t));
  return num;
}

auto HashInputs(const std::vector<uint128_t>& elem_hashes, size_t count) {
  size_t num_bins = std::ceil(count * ZETA);
  std::vector<std::vector<uint128_t>> hashing(num_bins);
  for (auto elem : elem_hashes) {
    auto hash = HashU128{}(elem);
    hashing[hash % num_bins].push_back(elem);
  }
  return hashing;
}

auto Evaluate(const std::vector<uint64_t>& coeffs, uint64_t x) {
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

void KrtwPsuSend(std::shared_ptr<yacl::link::Context> ctx,
                 const std::vector<uint128_t>& elem_hashes) {
  ctx->SendAsync(ctx->NextRank(), Serialize(elem_hashes.size()),
                 "Send set size");
  size_t peer_count =
      Deserialize(ctx->Recv(ctx->PrevRank(), "Receive set size"));
  auto count = std::max(elem_hashes.size(), peer_count);
  if (count == 0) {
    return;
  }
  // Step 1. Hashes inputs
  auto hashing = HashInputs(elem_hashes, count);

  // Step 2. Prepares OPRF
  yc::KkrtOtExtReceiver receiver;
  size_t num_ot{hashing.size() * BIN_SIZE};
  auto choice = yc::RandBits(NUM_BASE_OT);
  auto base_ot = yc::BaseOtRecv(ctx, choice, NUM_BASE_OT);
  auto store = yc::IknpOtExtSend(ctx, base_ot, NUM_INKP_OT);
  receiver.Init(ctx, store, num_ot);
  receiver.SetBatchSize(BATCH_SIZE);

  std::vector<uint128_t> elems;
  elems.reserve(num_ot);
  size_t oprf_idx{};
  for (size_t bin_idx{}; bin_idx != hashing.size(); ++bin_idx) {
    if (bin_idx % NUM_BIN_PER_BATCH == 0) {
      receiver.SendCorrection(
          ctx, std::min(BATCH_SIZE, (hashing.size() - bin_idx) * BIN_SIZE));
    }
    hashing[bin_idx].resize(BIN_SIZE);
    std::shuffle(hashing[bin_idx].begin(), hashing[bin_idx].end(), gen);
    // Step 3. For each bin element, invokes PSU(1, m+1)
    for (auto elem : hashing[bin_idx]) {
      elems.emplace_back(elem);
      uint64_t eval;
      receiver.Encode(oprf_idx++, elem,
                      {reinterpret_cast<uint8_t*>(&eval), sizeof eval});
      std::vector<uint64_t> coeffs(BIN_SIZE);
      auto buf = ctx->Recv(ctx->PrevRank(), "Receive coefficients");
      std::memcpy(coeffs.data(), buf.data(), buf.size());
      auto y = Evaluate(coeffs, HashU128{}(elem)) ^ eval;
      ctx->SendAsync(ctx->NextRank(), Serialize(y), "Send evaluation");
    }
  }

  // Step 4. Send new elements through OT
  std::vector<std::array<uint128_t, 2>> keys(num_ot);
  choice = yc::RandBits(NUM_BASE_OT);
  base_ot = yc::BaseOtRecv(ctx, choice, NUM_BASE_OT);
  yc::IknpOtExtSend(ctx, base_ot, absl::MakeSpan(keys));
  std::vector<uint128_t> ciphers(num_ot);
  for (size_t i{}; i != num_ot; ++i) {
    ciphers[i] = elems[i] ^ keys[i][0];
  }
  ctx->SendAsync(ctx->NextRank(),
                 yacl::Buffer{reinterpret_cast<uint8_t*>(ciphers.data()),
                              ciphers.size() * sizeof(uint128_t)},
                 "Send ciphertexts");
}

std::vector<uint128_t> KrtwPsuRecv(std::shared_ptr<yacl::link::Context> ctx,
                                   const std::vector<uint128_t>& elem_hashes) {
  size_t peer_count =
      Deserialize(ctx->Recv(ctx->PrevRank(), "Receive set size"));
  ctx->SendAsync(ctx->NextRank(), Serialize(elem_hashes.size()),
                 "Send set size");
  auto count = std::max(elem_hashes.size(), peer_count);
  if (count == 0) {
    return {};
  }
  // Step 1. Hashes inputs
  auto hashing = HashInputs(elem_hashes, count);

  // Step 2. Prepares OPRF
  yc::KkrtOtExtSender sender;
  size_t num_ot{hashing.size() * BIN_SIZE};
  auto base_ot = yc::BaseOtSend(ctx, NUM_BASE_OT);
  auto choice = yc::RandBits(NUM_INKP_OT);
  auto store = yc::IknpOtExtRecv(ctx, base_ot, choice, NUM_INKP_OT);
  sender.Init(ctx, store, num_ot);
  sender.SetBatchSize(BATCH_SIZE);
  auto oprf = sender.GetOprf();

  yacl::dynamic_bitset<> ot_choice(num_ot);
  size_t oprf_idx{};
  // Step 3. For each bin, invokes PSU(1, m+1)
  for (size_t bin_idx{}; bin_idx != hashing.size(); ++bin_idx) {
    if (bin_idx % NUM_BIN_PER_BATCH == 0) {
      sender.RecvCorrection(
          ctx, std::min(BATCH_SIZE, (hashing.size() - bin_idx) * BIN_SIZE));
    }
    auto bin_size = hashing[bin_idx].size();
    for (size_t elem_idx{}; elem_idx != BIN_SIZE; ++elem_idx, ++oprf_idx) {
      auto seed = yc::FastRandU64();
      std::vector<uint64_t> xs(BIN_SIZE), ys(BIN_SIZE);
      for (size_t i{}; i != BIN_SIZE; ++i) {
        xs[i] = (i < bin_size   ? HashU128{}(hashing[bin_idx][i])
                 : i > bin_size ? yc::FastRandU64()
                                : BOT);
        ys[i] = oprf->Eval(oprf_idx, xs[i]) ^ seed;
      }
      auto coeffs = Interpolate(xs, ys);
      yacl::Buffer buf(coeffs.data(), coeffs.size() * sizeof(uint64_t));
      ctx->SendAsync(ctx->NextRank(), buf, "Send coefficients");
      auto eval = Deserialize(ctx->Recv(ctx->PrevRank(), "Receive evaluation"));
      ot_choice[oprf_idx] = eval == seed;
    }
  }

  // Step 4. Receive new elements through OT
  std::vector<uint128_t> keys(num_ot);
  base_ot = yc::BaseOtSend(ctx, NUM_BASE_OT);
  yc::IknpOtExtRecv(ctx, base_ot, ot_choice, absl::MakeSpan(keys));
  std::vector<uint128_t> ciphers(num_ot);
  auto buf = ctx->Recv(ctx->PrevRank(), "Receive ciphertexts");
  std::memcpy(ciphers.data(), buf.data(), buf.size());
  std::unordered_set<uint128_t, HashU128> set_union(elem_hashes.begin(),
                                                    elem_hashes.end());
  for (size_t i{}; i != num_ot; ++i) {
    if (!ot_choice[i]) {
      if (auto new_elem = ciphers[i] ^ keys[i]; new_elem != BOT) {
        set_union.emplace(ciphers[i] ^ keys[i]);
      }
    }
  }
  return std::vector(set_union.begin(), set_union.end());
}

}  // namespace yacl::crypto::psu
