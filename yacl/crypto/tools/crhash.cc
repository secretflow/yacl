// Copyright 2022 Ant Group Co., Ltd.
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

#include "yacl/crypto/tools/crhash.h"

#include "yacl/math/galois_field/gf_intrinsic.h"

#ifndef __aarch64__
// sse
#include <emmintrin.h>
#include <smmintrin.h>
// pclmul
#include <wmmintrin.h>
#else
#include "sse2neon.h"
#endif

namespace yacl::crypto {

namespace {
constexpr uint64_t kBatchSize = 1024;

// Circular Correlation Robust Hash function (Single Block)
// See https://eprint.iacr.org/2019/074.pdf Sec 7.3
// CcrHash = RP(Sigma(x)) ^ Sigma(x)
// Sigma(x) = (x.left ^ x.right) || x.left
inline uint128_t Sigma(uint128_t x) {
  auto _x = _mm_loadu_si128(reinterpret_cast<__m128i*>(&x));
  auto exchange = _mm_shuffle_epi32(_x, 0b01001110);
  auto left = _mm_unpackhi_epi64(_x, _mm_setzero_si128());
  return reinterpret_cast<uint128_t>(_mm_xor_si128(exchange, left));
}

inline std::vector<uint128_t> Sigma(absl::Span<const uint128_t> x) {
  const uint32_t num = x.size();

  std::vector<uint128_t> ret(num);
  auto zero = _mm_setzero_si128();
  auto* dst = reinterpret_cast<__m128i*>(ret.data());
  const auto* src = reinterpret_cast<const __m128i*>(x.data());
  const auto* end = src + num;
  for (; src != end; ++src, ++dst) {
    auto _xi = _mm_loadu_si128(src);  // _xi = x[i]
    // exchange = _xi.right || _xi.left
    auto exchange = _mm_shuffle_epi32(_xi, 0b01001110);
    // high  = _xi.left || zero
    auto left = _mm_unpacklo_epi64(_xi, zero);
    // _xi.left xor _xi.right || _xi.left
    _mm_storeu_si128(dst, _mm_xor_si128(exchange, left));
  }
  return ret;
}

inline void SigmaInplace(absl::Span<uint128_t> x) {
  const uint32_t num = x.size();
  auto zero = _mm_setzero_si128();
  auto* ptr = reinterpret_cast<__m128i*>(x.data());
  auto* end = ptr + num;
  for (; ptr != end; ++ptr) {
    auto _xi = _mm_loadu_si128(ptr);  // _xi = x[i]
    // exchange = _xi.right || _xi.left
    auto exchange = _mm_shuffle_epi32(_xi, 0b01001110);
    // high  = _xi.left || zero
    auto left = _mm_unpacklo_epi64(_xi, zero);
    // _xi.left xor _xi.right || _xi.left
    _mm_storeu_si128(ptr, _mm_xor_si128(exchange, left));
  }
}

RP& GetCrHashDefaultRP() {
  static RP rp(RP::Ctype::AES128_ECB, RP::kDefaultRpKey, RP::kDefaultRpIV);
  return rp;
}

}  // namespace

uint128_t CrHash_128(uint128_t x) {
  const auto& RP = GetCrHashDefaultRP();
  return RP.Gen(x) ^ x;
}

// FIXME: Rename to BatchCrHash_128
std::vector<uint128_t> ParaCrHash_128(absl::Span<const uint128_t> x) {
  std::vector<uint128_t> out(x.size());
  const auto& RP = GetCrHashDefaultRP();
  RP.GenForMultiInputs(x, absl::MakeSpan(out));
  std::transform(x.begin(), x.end(), out.begin(), out.begin(),
                 std::bit_xor<uint128_t>());
  return out;
}

// FIXME: Rename to BatchCrHashInplace_128
void ParaCrHashInplace_128(absl::Span<uint128_t> inout) {
  const auto& RP = GetCrHashDefaultRP();
  // TODO: add dynamic batch size
  alignas(32) std::array<uint128_t, kBatchSize> tmp;
  auto tmp_span = absl::MakeSpan(tmp);
  const uint64_t size = inout.size();

  uint64_t offset = 0;
  for (; offset + kBatchSize <= size; offset += kBatchSize) {
    auto inout_span = inout.subspan(offset, kBatchSize);
    RP.GenForMultiInputs(inout_span, tmp_span);
    std::transform(tmp_span.begin(), tmp_span.begin() + kBatchSize,
                   inout_span.begin(), inout_span.begin(),
                   std::bit_xor<uint128_t>());
  }
  uint64_t remain = size - offset;
  if (remain > 0) {
    auto inout_span = inout.subspan(offset, remain);
    RP.GenForMultiInputs(inout_span, tmp_span.subspan(0, remain));
    std::transform(tmp_span.begin(), tmp_span.begin() + remain,
                   inout_span.begin(), inout_span.begin(),
                   std::bit_xor<uint128_t>());
  }
}

uint128_t CcrHash_128(uint128_t x) { return CrHash_128(Sigma(x)); }

// FIXME: Rename to BatchCcrHash_128
std::vector<uint128_t> ParaCcrHash_128(absl::Span<const uint128_t> x) {
  auto tmp = Sigma(x);
  ParaCrHashInplace_128(absl::MakeSpan(tmp));
  return tmp;
}

// FIXME: Rename to BatchCcrHashInplace_128
void ParaCcrHashInplace_128(absl::Span<uint128_t> inout) {
  const uint64_t size = inout.size();
  uint64_t offset = 0;

  auto inout_span = absl::MakeSpan(inout);
  for (; offset + kBatchSize < size; offset += kBatchSize) {
    SigmaInplace(inout_span.subspan(offset, kBatchSize));
    ParaCrHashInplace_128(inout_span.subspan(offset, kBatchSize));
  }
  auto remain = size - offset;
  SigmaInplace(inout_span.subspan(offset, remain));
  ParaCrHashInplace_128(inout_span.subspan(offset, remain));
}

// Tweakable Circular Correlation Robust (TCCR) hash function
// We apply the more efficient construction proposed by Chen & Tessaro
// See https://eprint.iacr.org/2022/080.pdf
uint128_t TccrHash_128(uint128_t x, uint64_t i) {
  const auto& RP = GetCrHashDefaultRP();
  // This construction requires tweak != 0, 1 to satisfy TCCR.
  // We encode the tweak as t = 2^64 + i.
  const uint128_t tweak = yacl::MakeUint128(1, i);
  const uint128_t tmp = yacl::math::Gf128Mul(x, tweak);
  // TccrHash(x,t) = RP(x * t) ^ (x * t),
  // where * denotes multiplication in GF(2^128).
  return RP.Gen(tmp) ^ tmp;
}

// TccrHash(x,i) for elements in x, i begins with begin_index, return the result
std::vector<uint128_t> ParaTccrHash_128(absl::Span<const uint128_t> x,
                                        uint64_t begin_index) {
  std::vector<uint128_t> out(x.size());
  std::vector<uint128_t> tmp(x.size());
  const auto& RP = GetCrHashDefaultRP();

  // Encode the tweak t = 2^64 + i to ensure t != 0, 1.
  // tmp = x * t
  for (uint64_t i = 0; i < tmp.size(); i++) {
    const uint128_t tweak = MakeUint128(1, begin_index + i);
    tmp[i] = yacl::math::Gf128Mul(x[i], tweak);
  }
  // out = RP(tmp) = RP(x * t)
  RP.GenForMultiInputs(absl::MakeSpan(tmp), absl::MakeSpan(out));
  // out = tmp ^ out = RP(x * t) ^ (x * t)
  std::transform(tmp.begin(), tmp.end(), out.begin(), out.begin(),
                 std::bit_xor<uint128_t>());
  return out;
}

// TccrHash(x,i) for elements in inout (inplace), i begins with begin_index
void ParaTccrHashInplace_128(absl::Span<uint128_t> inout,
                             uint64_t begin_index) {
  const auto& RP = GetCrHashDefaultRP();
  // TODO: add dynamic batch size
  alignas(32) std::array<uint128_t, kBatchSize> tmp;
  auto tmp_span = absl::MakeSpan(tmp);
  const uint64_t size = inout.size();
  uint64_t i;

  uint64_t offset = 0;
  for (; offset + kBatchSize <= size; offset += kBatchSize) {
    auto inout_span = inout.subspan(offset, kBatchSize);
    // inout_span = x * t, where t = 2^64 + begin_index + offset + i
    for (i = 0; i < kBatchSize; i++) {
      const uint128_t tweak = MakeUint128(1, begin_index + offset + i);
      inout_span[i] = yacl::math::Gf128Mul(inout_span[i], tweak);
    }
    // tmp = x * t
    std::memcpy(tmp_span.data(), inout_span.data(),
                kBatchSize * sizeof(uint128_t));
    // tmp = RP(x * t)
    RP.GenForMultiInputsInplace(tmp_span);
    // inout_span = RP(x * t) ^ (x * t)
    std::transform(tmp_span.begin(), tmp_span.end(), inout_span.begin(),
                   inout_span.begin(), std::bit_xor<uint128_t>());
  }

  uint64_t remain = size - offset;
  if (remain > 0) {
    auto inout_span = inout.subspan(offset, remain);
    for (i = 0; i < remain; i++) {
      const uint128_t tweak = MakeUint128(1, begin_index + offset + i);
      inout_span[i] = yacl::math::Gf128Mul(inout_span[i], tweak);
    }
    std::memcpy(tmp_span.data(), inout_span.data(), remain * sizeof(uint128_t));
    RP.GenForMultiInputsInplace(tmp_span.subspan(0, remain));
    std::transform(tmp_span.begin(), tmp_span.begin() + remain,
                   inout_span.begin(), inout_span.begin(),
                   std::bit_xor<uint128_t>());
  }
}

}  // namespace yacl::crypto
