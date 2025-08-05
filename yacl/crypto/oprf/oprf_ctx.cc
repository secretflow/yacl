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
    std::array<char, 32> seed, const std::string& info) {
  constexpr std::string_view kDst = "DeriveKeyPair";

  Buffer derive_input(sizeof(seed) + 2 + info.size() + 1);
  char* p = derive_input.data<char>();

  // copy seed
  std::memcpy(p, &seed, sizeof(seed));
  p += sizeof(seed);

  // copy info size
  YACL_ENFORCE(info.size() < (1 << 16));
  uint64_t info_size = info.size();
  std::memcpy(p, I2OSP(info.size(), 2).data(), 2);
  p += 2;
  // copy info
  std::memcpy(p, info.data(), info_size);
  p += info_size;

  int counter = 0;
  SkTy sk = 0_mp;
  PkTy pk;
  while (sk == 0_mp) {
    YACL_ENFORCE(counter <= 255, "DeriveKeyPairError");
    std::memcpy(p, I2OSP(counter, 1).data(), 1);
    p += 1;

    sk = HashToScalar(derive_input, std::string(kDst));
    counter++;
  }
  pk = ec_->MulBase(sk);
  return {sk, pk};
}
}  // namespace yacl::crypto
