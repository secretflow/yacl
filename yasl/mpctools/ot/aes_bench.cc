#include <future>
#include <iostream>
#include <random>

#include "benchmark/benchmark.h"
#include "emp-tool/utils/aes_opt.h"

#ifdef __x86_64
#include "crypto_mb/sm4.h"  // ipp-crypto multi-buffer
#include "ippcp.h"          // ipp-crypto
#endif

#include "yasl/crypto/pseudo_random_generator.h"

constexpr uint128_t kIv1 = 1;

static void BM_OpensslAes(benchmark::State& state) {
  std::array<uint128_t, 1> plain_u128;
  uint128_t key_u128;

  std::random_device rd;
  yasl::PseudoRandomGenerator<uint128_t> prg(rd());

  key_u128 = prg();
  plain_u128[0] = prg();

  auto type = yasl::SymmetricCrypto::CryptoType::AES128_ECB;
  yasl::SymmetricCrypto crypto(type, key_u128, kIv1);
  std::array<uint128_t, 1> encrypted_u128;

  for (auto _ : state) {
    state.PauseTiming();
    size_t n = state.range(0);
    state.ResumeTiming();
    for (size_t i = 0; i < n; i++) {
      crypto.Encrypt(absl::MakeConstSpan(plain_u128),
                     absl::MakeSpan(encrypted_u128));
      plain_u128[0] = encrypted_u128[0];
    }
  }
}

struct emp_block {
  emp::block block;
};

static void BM_EmpToolAes(benchmark::State& state) {
  emp_block key_block, plain_block;

  std::random_device rd;
  yasl::PseudoRandomGenerator<emp_block> prg(rd());

  key_block = prg();
  plain_block = prg();

  emp::AES_KEY aes_key;
  emp::AES_set_encrypt_key(key_block.block, &aes_key);

  for (auto _ : state) {
    state.PauseTiming();
    size_t n = state.range(0);
    state.ResumeTiming();
    for (size_t i = 0; i < n; i++) {
      emp::AES_ecb_encrypt_blks(&plain_block.block, 1, &aes_key);
    }
  }
}

constexpr uint64_t kKeyWidth = 4;

static void BM_EmpToolMultiAes(benchmark::State& state) {
  emp::block keys_block[kKeyWidth];
  emp::block plain_block[kKeyWidth];

  std::random_device rd;
  yasl::PseudoRandomGenerator<emp_block> prg(rd());

  emp_block eb;
  for (uint64_t i = 0; i < kKeyWidth; ++i) {
    eb = prg();
    keys_block[i] = eb.block;
    eb = prg();
    plain_block[i] = eb.block;
  }

  emp::AES_KEY aes_key[kKeyWidth];

  emp::AES_opt_key_schedule<kKeyWidth>(keys_block, aes_key);

  for (auto _ : state) {
    state.PauseTiming();
    size_t n = state.range(0);
    state.ResumeTiming();
    for (size_t i = 0; i < n; i++) {
      emp::ParaEnc<kKeyWidth, kKeyWidth>(plain_block, aes_key);
    }
  }
}

#ifdef __x86_64
static void BM_IppcpAes(benchmark::State& state) {
  uint128_t key_u128, plain_u128;

  std::random_device rd;
  yasl::PseudoRandomGenerator<uint128_t> prg(rd());

  key_u128 = prg();

  plain_u128 = prg();

  int aes_ctx_size;
  IppStatus status = ippsAESGetSize(&aes_ctx_size);

  IppsAESSpec* aes_ctx_ptr = (IppsAESSpec*)(new Ipp8u[aes_ctx_size]);
  status = ippsAESInit((Ipp8u*)&key_u128, 16, aes_ctx_ptr, aes_ctx_size);
  YASL_ENFORCE(status == ippStsNoErr, "ippsAESInit error");

  Ipp8u plain_data[16], encrypted_data[16], iv_data[16];
  std::memcpy(plain_data, (Ipp8u*)&plain_u128, 16);
  std::memset(iv_data, 0, 16);

  for (auto _ : state) {
    state.PauseTiming();
    size_t n = state.range(0);
    state.ResumeTiming();
    for (size_t i = 0; i < n; i++) {
      ippsAESEncryptCBC(plain_data, encrypted_data, 16, aes_ctx_ptr, iv_data);
      std::memcpy(plain_data, encrypted_data, 16);
    }
  }

  delete[](Ipp8u*) aes_ctx_ptr;
}

static void BM_IppcpSm4(benchmark::State& state) {
  uint128_t key_u128, plain_u128;

  std::random_device rd;
  yasl::PseudoRandomGenerator<uint128_t> prg(rd());

  key_u128 = prg();

  plain_u128 = prg();

  int sm4_ctx_size;
  IppStatus status = ippsSMS4GetSize(&sm4_ctx_size);

  IppsSMS4Spec* sm4_ctx_ptr = (IppsSMS4Spec*)(new Ipp8u[sm4_ctx_size]);
  status = ippsSMS4Init((Ipp8u*)&key_u128, 16, sm4_ctx_ptr, sm4_ctx_size);
  YASL_ENFORCE(status == ippStsNoErr, "ippsSM4Init error");

  Ipp8u plain_data[16], encrypted_data[16], iv_data[16];
  std::memcpy(plain_data, (Ipp8u*)&plain_u128, 16);
  std::memset(iv_data, 0, 16);

  for (auto _ : state) {
    state.PauseTiming();
    size_t n = state.range(0);
    state.ResumeTiming();
    for (size_t i = 0; i < n; i++) {
      ippsSMS4EncryptCBC(plain_data, encrypted_data, 16, sm4_ctx_ptr, iv_data);
      std::memcpy(plain_data, encrypted_data, 16);
    }
  }

  delete[](Ipp8u*) sm4_ctx_ptr;
}
#endif

BENCHMARK(BM_OpensslAes)
    ->Unit(benchmark::kMillisecond)
    ->Arg(1024)
    ->Arg(5120)
    ->Arg(10240)
    ->Arg(20480)
    ->Arg(40960)
    ->Arg(81920)
    ->Arg(1 << 24);

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

BENCHMARK(BM_EmpToolAes)
    ->Unit(benchmark::kMillisecond)
    ->Arg(1024)
    ->Arg(5120)
    ->Arg(10240)
    ->Arg(20480)
    ->Arg(40960)
    ->Arg(81920)
    ->Arg(1 << 24);

BENCHMARK(BM_EmpToolMultiAes)
    ->Unit(benchmark::kMillisecond)
    ->Arg(256)
    ->Arg(1280)
    ->Arg(2560)
    ->Arg(5120)
    ->Arg(10240)
    ->Arg(20480)
    ->Arg(1 << 22);

BENCHMARK_MAIN();
