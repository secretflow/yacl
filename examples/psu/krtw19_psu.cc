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

#include "examples/psu/krtw19_psu.h"

#include <algorithm>
#include <cstdint>
#include <iterator>
#include <vector>

#include "yacl/utils/serialize.h"

namespace examples::psu {

namespace {

// reference: https://eprint.iacr.org/2019/1234.pdf (Figure 2)
constexpr float kZeta{0.06f};
constexpr size_t kBinSize{64ul};  // m+1
constexpr uint128_t kBot{0};
constexpr size_t kNumBinsPerBatch{16ul};
constexpr size_t kBatchSize{kNumBinsPerBatch * kBinSize};
constexpr size_t kNumInkpOT{512ul};

static auto HashToSizeT = [](const uint128_t& x) {
  auto hash = yacl::crypto::Blake3_128({&x, sizeof(x)});
  size_t ret;
  std::memcpy(&ret, &hash, sizeof(ret));
  return ret;
};

auto HashInputs(const std::vector<uint128_t>& elem_hashes, size_t count) {
  size_t num_bins = std::ceil(count * kZeta);
  std::vector<std::vector<uint128_t>> hashing(num_bins);
  for (const auto& elem : elem_hashes) {
    auto hash = HashToSizeT(elem);
    hashing[hash % num_bins].emplace_back(elem);
  }
  return hashing;
}

}  // namespace

uint64_t Evaluate(const std::vector<uint64_t>& coeffs, uint64_t x) {
  uint64_t y = coeffs.back();
  for (auto it = std::next(coeffs.rbegin()); it != coeffs.rend(); ++it) {
    y = yacl::GfMul64(y, x) ^ *it;
  }
  return y;
}

std::vector<uint64_t> Interpolate(const std::vector<uint64_t>& xs,
                                  const std::vector<uint64_t>& ys) {
  YACL_ENFORCE(xs.size() == ys.size());
  auto size = xs.size();
  auto poly = std::vector<uint64_t>(size + 1, 0);

  // Compute poly = (x - x0)(x - x1) ... (x - xn)
  poly[0] = 1;
  for (size_t j = 0; j < size; ++j) {
    uint64_t sum = 0;
    for (size_t k = 0; k <= j + 1; ++k) {
      sum = std::exchange(poly[k], yacl::GfMul64(poly[k], xs[j]) ^ sum);
    }
  }

  auto coeffs = std::vector<uint64_t>(size, 0);  // result

  for (size_t i = 0; i < size; ++i) {
    // subpoly = poly / (x - xi)
    auto subpoly = std::vector<uint64_t>(size, 0);
    uint64_t xi = xs[i];
    subpoly[size - 1] = 1;
    for (int32_t k = size - 2; k >= 0; --k) {
      subpoly[k] = poly[k + 1] ^ yacl::GfMul64(subpoly[k + 1], xi);
    }

    auto prod = yacl::GfMul64(ys[i], yacl::GfInv64(Evaluate(subpoly, xi)));
    // update coeff
    for (size_t k = 0; k < size; ++k) {
      coeffs[k] = coeffs[k] ^ yacl::GfMul64(subpoly[k], prod);
    }
  }

  return coeffs;
}

void KrtwPsuSend(const std::shared_ptr<yacl::link::Context>& ctx,
                 const std::vector<uint128_t>& elem_hashes) {
  ctx->SendAsync(ctx->NextRank(), yacl::SerializeUint128(elem_hashes.size()),
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
  yacl::crypto::KkrtOtExtReceiver receiver;
  const size_t num_ot = hashing.size() * kBinSize;
  auto ss_sender = yacl::crypto::SoftspokenOtExtSender();
  auto store = ss_sender.GenRot(ctx, kNumInkpOT);

  receiver.Init(ctx, store, num_ot);
  receiver.SetBatchSize(kBatchSize);

  std::vector<uint128_t> elems;
  elems.reserve(num_ot);
  size_t oprf_idx = 0;
  for (size_t bin_idx = 0; bin_idx != hashing.size(); ++bin_idx) {
    hashing[bin_idx].resize(kBinSize);
    std::sort(hashing[bin_idx].begin(), hashing[bin_idx].end());
    std::vector<uint64_t> evals(kBinSize);

    // Encode inputs before SendCorrection
    // More details could be found in `yacl/kernel/algorithms/kkrt_ote_test.cc`
    std::transform(hashing[bin_idx].cbegin(), hashing[bin_idx].cend(),
                   evals.begin(), [&](uint128_t input) {
                     uint64_t result;
                     receiver.Encode(
                         oprf_idx, HashToSizeT(input),
                         {reinterpret_cast<uint8_t*>(&result), sizeof(result)});
                     oprf_idx++;
                     return result;
                   });
    receiver.SendCorrection(ctx, kBinSize);

    // Step 3. For each bin element, invokes PSU(1, m+1)
    for (size_t i = 0; i < hashing[bin_idx].size(); ++i) {
      auto elem = hashing[bin_idx][i];
      elems.emplace_back(elem);
      uint64_t eval = evals[i];
      std::vector<uint64_t> coeffs(kBinSize);
      auto buf = ctx->Recv(ctx->PrevRank(), "Receive coefficients");

      YACL_ENFORCE(buf.size() == kBinSize * sizeof(uint64_t));
      std::memcpy(coeffs.data(), buf.data(), buf.size());

      auto y = Evaluate(coeffs, HashToSizeT(elem)) ^ eval;
      ctx->SendAsync(ctx->NextRank(),
                     yacl::SerializeUint128(yacl::MakeUint128(0, y)),
                     "Send evaluation");
    }
  }

  // Step 4. Sends new elements through OT
  auto keys = ss_sender.GenRot(ctx, num_ot);
  std::vector<uint128_t> ciphers(num_ot);
  for (size_t i = 0; i != num_ot; ++i) {
    ciphers[i] = elems[i] ^ keys.GetBlock(i, 0);
  }
  ctx->SendAsync(ctx->NextRank(),
                 yacl::ByteContainerView(ciphers.data(),
                                         ciphers.size() * sizeof(uint128_t)),
                 "Send ciphertexts");
}

std::vector<uint128_t> KrtwPsuRecv(
    const std::shared_ptr<yacl::link::Context>& ctx,
    const std::vector<uint128_t>& elem_hashes) {
  size_t peer_count =
      DeserializeUint128(ctx->Recv(ctx->PrevRank(), "Receive set size"));
  ctx->SendAsync(ctx->NextRank(), yacl::SerializeUint128(elem_hashes.size()),
                 "Send set size");
  auto count = std::max(elem_hashes.size(), peer_count);
  if (count == 0) {
    return {};
  }
  // Step 1. Hashes inputs
  auto hashing = HashInputs(elem_hashes, count);

  // Step 2. Prepares OPRF
  const size_t num_ot = hashing.size() * kBinSize;
  auto ss_receiver = yacl::crypto::SoftspokenOtExtReceiver();
  auto store = ss_receiver.GenRot(ctx, kNumInkpOT);

  yacl::crypto::KkrtOtExtSender sender;
  sender.Init(ctx, store, num_ot);
  sender.SetBatchSize(kBatchSize);
  auto oprf = sender.GetOprf();

  yacl::dynamic_bitset<uint128_t> ot_choice(num_ot);
  size_t oprf_idx = 0;
  // Step 3. For each bin, invokes PSU(1, m+1)
  for (size_t bin_idx = 0; bin_idx != hashing.size(); ++bin_idx) {
    sender.RecvCorrection(ctx, kBinSize);

    auto bin_size = hashing[bin_idx].size();
    for (size_t elem_idx = 0; elem_idx != kBinSize; ++elem_idx, ++oprf_idx) {
      auto seed = yacl::crypto::FastRandU64();
      std::vector<uint64_t> xs(kBinSize), ys(kBinSize);
      for (size_t i = 0; i != kBinSize; ++i) {
        xs[i] = (i < bin_size   ? HashToSizeT(hashing[bin_idx][i])
                 : i > bin_size ? yacl::crypto::FastRandU64()
                                : kBot);
        oprf->Eval(oprf_idx, xs[i], reinterpret_cast<uint8_t*>(&ys[i]),
                   sizeof(ys[i]));
        ys[i] ^= seed;
      }
      std::vector<uint64_t> coeffs = Interpolate(xs, ys);
      ctx->SendAsync(ctx->NextRank(),
                     yacl::ByteContainerView(coeffs.data(),
                                             coeffs.size() * sizeof(uint64_t)),
                     "Send coefficients");
      auto eval = yacl::DeserializeUint128(
          ctx->Recv(ctx->PrevRank(), "Receive evaluation"));
      ot_choice[oprf_idx] = (eval == yacl::MakeUint128(0, seed));
    }
  }

  // Step 4. Receives new elements through OT
  auto keys = ss_receiver.GenRot(ctx, ot_choice);
  std::vector<uint128_t> ciphers(num_ot);
  auto buf = ctx->Recv(ctx->PrevRank(), "Receive ciphertexts");
  YACL_ENFORCE(buf.size() == int64_t(num_ot * sizeof(uint128_t)));
  std::memcpy(ciphers.data(), buf.data(), buf.size());

  std::set<uint128_t> set_union(elem_hashes.begin(), elem_hashes.end());

  for (size_t i = 0; i != num_ot; ++i) {
    if (!ot_choice[i]) {
      auto new_elem = ciphers[i] ^ keys.GetBlock(i);
      if (new_elem != kBot) {
        set_union.emplace(new_elem);
      }
    }
  }
  return std::vector(set_union.begin(), set_union.end());
}

}  // namespace examples::psu
