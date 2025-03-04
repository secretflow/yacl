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

#include "yacl/crypto/oprf/oprf_ctx.h"

#include "yacl/crypto/hash/ssl_hash.h"

namespace yacl::crypto {

std::pair<OprfCtx::SkTy, OprfCtx::PkTy> OprfCtx::GenKeyPair() {
  SkTy sk;
  math::MPInt::RandomLtN(ec_->GetOrder(), &sk);
  PkTy pk = ec_->MulBase(sk);
  return {sk, pk};
}

std::pair<OprfCtx::SkTy, OprfCtx::PkTy> OprfCtx::DeriveKeyPair(
    uint128_t seed, const std::string& info) {
  constexpr std::string_view kDst = "DeriveKeyPair";

  YACL_ENFORCE(info.size() < (1 << 16));
  uint16_t info_size = info.size();
  uint8_t counter = 0;
  uint64_t n = sizeof(seed) + sizeof(info_size) + info_size + 1 + kDst.size() +
               ctx_str_.size();
  Buffer derive_input(static_cast<uint64_t>(n));
  char* p = derive_input.data<char>();

  // copy seed
  std::memcpy(p, &seed, sizeof(uint128_t));
  p += sizeof(uint128_t);

  // copy info size
  std::memcpy(p, &info_size, sizeof(info_size));
  p += sizeof(info_size);

  // copy info
  snprintf(p, info.size(), "%s", info.data());
  p += info_size;

  // copy counter
  *p = static_cast<char>(counter);
  p++;

  // copy dst
  std::memcpy(p, kDst.data(), kDst.size());
  p += kDst.size();

  // copy ctx_str
  std::memcpy(p, ctx_str_.data(), ctx_str_.size());

  SkTy sk;
  PkTy pk;
  while (sk == 0_mp) {
    YACL_ENFORCE(counter <= 255);
    auto hash_buf = SslHash(hash_).Update(derive_input).CumulativeHash();
    sk.FromMagBytes(hash_buf, Endian::little);
    math::MPInt::Mod(sk, ec_->GetOrder(), &sk);
    counter++;
    pk = ec_->MulBase(sk);
  }
  return {sk, pk};
}
}  // namespace yacl::crypto
