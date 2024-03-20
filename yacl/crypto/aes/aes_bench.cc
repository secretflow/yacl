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

#include <future>
#include <iostream>
#include <random>

#include "benchmark/benchmark.h"

#include "yacl/crypto/aes/aes_opt.h"
#include "yacl/crypto/rand/rand.h"
#include "yacl/crypto/tools/prg.h"

namespace yacl::crypto {

constexpr uint128_t kIv1 = 1;

static void BM_OpensslAesEcb(benchmark::State& state) {
  for (auto _ : state) {
    state.PauseTiming();

    // setup input
    size_t n = state.range(0);
    Prg<uint128_t> prg(FastRandSeed());
    uint128_t key_u128 = FastRandU128();
    std::vector<uint128_t> plain_u128(n);
    std::vector<uint128_t> cipher_u128(n);
    for (size_t i = 0; i < n; i++) {
      plain_u128[i] = prg();
    }

    // setup context
    auto type = SymmetricCrypto::CryptoType::AES128_ECB;
    SymmetricCrypto crypto(type, key_u128, kIv1);

    state.ResumeTiming();

    crypto.Encrypt(absl::MakeConstSpan(plain_u128),
                   absl::MakeSpan(cipher_u128));
  }
}

static void BM_AesNiEcb(benchmark::State& state) {
  for (auto _ : state) {
    state.PauseTiming();

    // setup input
    size_t n = state.range(0);
    Prg<uint128_t> prg(FastRandSeed());
    uint128_t key_u128 = FastRandU128();
    std::vector<uint128_t> plain_u128(n);
    std::vector<uint128_t> cipher_u128(n);
    for (size_t i = 0; i < n; i++) {
      plain_u128[i] = prg();
    }

    // setup context
    auto aes_key = AES_set_encrypt_key(key_u128);

    state.ResumeTiming();

    AES_ecb_encrypt_blks(aes_key, plain_u128.data(), plain_u128.size(),
                         cipher_u128.data());
  }
}

// FIXME: the follwoing causes CI build error, find out why
// constexpr uint64_t kKeyWidth = 4;
// static void BM_MultiKeyAesEcb(benchmark::State& state) {
//   for (auto _ : state) {
//     state.PauseTiming();
//     std::array<uint128_t, kKeyWidth> keys_block;
//     std::array<uint128_t, kKeyWidth> plain_block;

//     std::random_device rd;
//     Prg<uint128_t> prg(rd());

//     for (uint64_t i = 0; i < kKeyWidth; ++i) {
//       keys_block[i] = prg();
//       plain_block[i] = prg();
//     }

//     std::array<AES_KEY, kKeyWidth> aes_key;
//     for (size_t idx = 0; idx < kKeyWidth; ++idx) {
//       aes_key[idx] = AES_set_encrypt_key(idx);
//     }

//     AES_opt_key_schedule<kKeyWidth>(keys_block.data(), aes_key.data());
//     size_t n = state.range(0);
//     state.ResumeTiming();

//     for (size_t i = 0; i < n; i++) {
//       ParaEnc<kKeyWidth, 1>(plain_block.data(), aes_key.data());
//     }
//   }
// }

BENCHMARK(BM_OpensslAesEcb)
    ->Unit(benchmark::kMillisecond)
    ->Arg(128)  // Buffer size for CrHash / CcrHash
    ->Arg(256)
    ->Arg(512)
    ->Arg(1024)
    ->Arg(5120)
    ->Arg(10240)
    ->Arg(20480)
    ->Arg(40960)
    ->Arg(81920)
    ->Arg(1 << 24);

BENCHMARK(BM_AesNiEcb)
    ->Unit(benchmark::kMillisecond)
    ->Arg(128)  // Buffer size for CrHash / CcrHash
    ->Arg(256)
    ->Arg(512)
    ->Arg(1024)
    ->Arg(5120)
    ->Arg(10240)
    ->Arg(20480)
    ->Arg(40960)
    ->Arg(81920)
    ->Arg(1 << 24);

// BENCHMARK(BM_MultiKeyAesEcb)
//     ->Unit(benchmark::kMillisecond)
//     ->Arg(256)
//     ->Arg(1280)
//     ->Arg(2560)
//     ->Arg(5120)
//     ->Arg(10240)
//     ->Arg(20480)
//     ->Arg(1 << 22);

}  // namespace yacl::crypto
