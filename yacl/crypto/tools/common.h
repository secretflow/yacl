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

#pragma once
#include "yacl/crypto/rand/rand.h"
#include "yacl/link/link.h"
#include "yacl/utils/serialize.h"

namespace yacl::crypto {
// -----------------------
//   sync seed protocol
// -----------------------
uint128_t inline SyncSeedSend(const std::shared_ptr<link::Context>& ctx) {
  uint128_t seed = SecureRandSeed();
  ctx->SendAsync(ctx->NextRank(), SerializeUint128(seed), "SyncSeed");
  return seed;
}

uint128_t inline SyncSeedRecv(const std::shared_ptr<link::Context>& ctx) {
  auto buf = ctx->Recv(ctx->NextRank(), "SyncSeed");
  return DeserializeUint128(buf);
}

}  // namespace yacl::crypto
