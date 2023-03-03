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

#include "yacl/crypto/base/aes/aes_opt.h"
#include "yacl/crypto/utils/rand.h"

#ifdef __x86_64
#include "crypto_mb/sm4.h"  // ipp-crypto multi-buffer
#include "ippcp.h"          // ipp-crypto
#endif

#include "yacl/crypto/tools/prg.h"

namespace yacl::crypto {

constexpr uint128_t kIv1 = 1;

static void BM_OpensslAesEcb(benchmark::State& state) {
  for (auto _ : state) {
    state.PauseTiming();

    // setup input
    size_t n = state.range(0);
    Prg<uint128_t> prg(RandSeed());
    uint128_t key_u128 = RandU128();
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
    Prg<uint128_t> prg(RandSeed());
    uint128_t key_u128 = RandU128();
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

constexpr uint64_t kKeyWidth = 4;

static void BM_MultiKeyAesEcb(benchmark::State& state) {
  for (auto _ : state) {
    state.PauseTiming();
    uint128_t keys_block[kKeyWidth];
    uint128_t plain_block[kKeyWidth];

    std::random_device rd;
    Prg<uint128_t> prg(rd());

    uint128_t eb;
    for (uint64_t i = 0; i < kKeyWidth; ++i) {
      eb = prg();
      keys_block[i] = eb;
      eb = prg();
      plain_block[i] = eb;
    }

    AES_KEY aes_key[kKeyWidth];

    AES_opt_key_schedule<kKeyWidth>(keys_block, aes_key);
    size_t n = state.range(0);
    state.ResumeTiming();

    for (size_t i = 0; i < n; i++) {
      ParaEnc<kKeyWidth, 1>(plain_block, aes_key);
    }
  }
}

#ifdef __x86_64
static void BM_IppcpAes(benchmark::State& state) {
  for (auto _ : state) {
    state.PauseTiming();
    uint128_t key_u128;
    uint128_t plain_u128;

    std::random_device rd;
    Prg<uint128_t> prg(rd());

    key_u128 = prg();

    plain_u128 = prg();

    int aes_ctx_size;
    IppStatus status = ippsAESGetSize(&aes_ctx_size);

    auto* aes_ctx_ptr = (IppsAESSpec*)(new Ipp8u[aes_ctx_size]);
    status = ippsAESInit((Ipp8u*)&key_u128, 16, aes_ctx_ptr, aes_ctx_size);
    YACL_ENFORCE(status == ippStsNoErr, "ippsAESInit error");

    Ipp8u plain_data[16];
    Ipp8u encrypted_data[16];
    Ipp8u iv_data[16];
    std::memcpy(plain_data, (Ipp8u*)&plain_u128, 16);
    std::memset(iv_data, 0, 16);

    size_t n = state.range(0);
    state.ResumeTiming();
    for (size_t i = 0; i < n; i++) {
      ippsAESEncryptCBC(plain_data, encrypted_data, 16, aes_ctx_ptr, iv_data);
      std::memcpy(plain_data, encrypted_data, 16);
    }
    delete[] (Ipp8u*)aes_ctx_ptr;
  }
}

static void BM_IppcpSm4(benchmark::State& state) {
  for (auto _ : state) {
    state.PauseTiming();
    uint128_t key_u128;
    uint128_t plain_u128;

    std::random_device rd;
    Prg<uint128_t> prg(rd());

    key_u128 = prg();

    plain_u128 = prg();

    int sm4_ctx_size;
    IppStatus status = ippsSMS4GetSize(&sm4_ctx_size);

    IppsSMS4Spec* sm4_ctx_ptr = (IppsSMS4Spec*)(new Ipp8u[sm4_ctx_size]);
    status = ippsSMS4Init((Ipp8u*)&key_u128, 16, sm4_ctx_ptr, sm4_ctx_size);
    YACL_ENFORCE(status == ippStsNoErr, "ippsSM4Init error");

    Ipp8u plain_data[16];
    Ipp8u encrypted_data[16];
    Ipp8u iv_data[16];
    std::memcpy(plain_data, (Ipp8u*)&plain_u128, 16);
    std::memset(iv_data, 0, 16);
    size_t n = state.range(0);
    state.ResumeTiming();
    for (size_t i = 0; i < n; i++) {
      ippsSMS4EncryptCBC(plain_data, encrypted_data, 16, sm4_ctx_ptr, iv_data);
      std::memcpy(plain_data, encrypted_data, 16);
    }
    delete[] (Ipp8u*)sm4_ctx_ptr;
  }
}
#endif

BENCHMARK(BM_OpensslAesEcb)
    ->Unit(benchmark::kMillisecond)
    ->Arg(1024)
    ->Arg(5120)
    ->Arg(10240)
    ->Arg(20480)
    ->Arg(40960)
    ->Arg(81920)
    ->Arg(1 << 24);

BENCHMARK(BM_AesNiEcb)
    ->Unit(benchmark::kMillisecond)
    ->Arg(1024)
    ->Arg(5120)
    ->Arg(10240)
    ->Arg(20480)
    ->Arg(40960)
    ->Arg(81920)
    ->Arg(1 << 24);

BENCHMARK(BM_MultiKeyAesEcb)
    ->Unit(benchmark::kMillisecond)
    ->Arg(256)
    ->Arg(1280)
    ->Arg(2560)
    ->Arg(5120)
    ->Arg(10240)
    ->Arg(20480)
    ->Arg(1 << 22);

#ifdef __x86_64
BENCHMARK(BM_IppcpAes)
    ->Unit(benchmark::kMillisecond)
    ->Arg(1024)
    ->Arg(5120)
    ->Arg(10240)
    ->Arg(20480)
    ->Arg(40960)
    ->Arg(81920)
    ->Arg(1 << 24);

BENCHMARK(BM_IppcpSm4)
    ->Unit(benchmark::kMillisecond)
    ->Arg(1024)
    ->Arg(5120)
    ->Arg(10240)
    ->Arg(20480)
    ->Arg(40960)
    ->Arg(81920)
    ->Arg(1 << 24);
#endif

}  // namespace yacl::crypto
