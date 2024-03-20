// Copyright 2023 Ant Group Co., Ltd.
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
#include "yacl/crypto/rand/drbg/ic_factory.h"

#include <algorithm>
#include <utility>

#include "yacl/base/int128.h"

namespace yacl::crypto {

namespace {
constexpr std::array<unsigned char, 8> kIcDrbgNonce = {0x20, 0x21, 0x22, 0x23,
                                                       0x24, 0x25, 0x26, 0x27};

constexpr std::array<unsigned char, 55> kIcDrbgPersonalStr = {
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A,
    0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55,
    0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60,
    0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B,
    0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76};

constexpr std::array<unsigned char, 55> kAdditionalInput = {
    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A,
    0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75,
    0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F, 0x80,
    0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B,
    0x8C, 0x8D, 0x8E, 0x8F, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96};

constexpr size_t kBatchSize = 1024;

}  // namespace

IcDrbg::IcDrbg(std::string type, bool use_yacl_es, SecParam::C secparam)
    : Drbg(use_yacl_es), type_(std::move(type)), secparam_(secparam) {
  YACL_ENFORCE(secparam_ <= SecParam::C::k256);
  uint128_t seed = 0;

  // default seeded using yacl's entropy source
  auto es = EntropySourceFactory::Instance().Create("auto");
  auto out_buf = es->GetEntropy(sizeof(uint128_t));
  std::memcpy(&seed, out_buf.data(), out_buf.size());
  SetSeed(seed);
}

void IcDrbg::SetSeed(uint128_t seed) {
  seed_ = seed;
  const EVP_MD *md = EVP_sha256();
  drbg_ctx_ = hash_drbg_ctx_new();
  hash_drbg_instantiate(md, reinterpret_cast<unsigned char *>(&seed_),
                        sizeof(uint128_t), (unsigned char *)kIcDrbgNonce.data(),
                        kIcDrbgNonce.size(),
                        (unsigned char *)kIcDrbgPersonalStr.data(),
                        kIcDrbgPersonalStr.size(), drbg_ctx_);
}

void IcDrbg::Fill(char *buf, size_t len) {
  YACL_ENFORCE(seed_ != 0, "Seed is not correctly configured!");

  const auto batch_num = (len + kBatchSize - 1) / kBatchSize;

  for (uint32_t step = 0; step < batch_num; step++) {
    const uint32_t limit = std::min(kBatchSize, len - step * kBatchSize);
    auto *offset = buf + step * kBatchSize;
    gen_rnd_bytes_with_hash_drbg(
        drbg_ctx_, limit, (unsigned char *)kAdditionalInput.data(),
        kAdditionalInput.size(), reinterpret_cast<unsigned char *>(offset));
  }
}

}  // namespace yacl::crypto
