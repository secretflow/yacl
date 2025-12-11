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

#include <array>
#include <cstring>
#include <memory>
#include <numeric>
#include <variant>
#include <vector>

#include "hash_drbg.h"              // from @hash_drbg//:hash_drbg
#include "hash_drbg_error_codes.h"  // from @hash_drbg//:hash_drbg
#include "spdlog/spdlog.h"

#include "yacl/base/byte_container_view.h"
#include "yacl/base/int128.h"
#include "yacl/crypto/openssl_wrappers.h"  // for TyHelper
#include "yacl/link/context.h"
#include "yacl/secparam.h"
#include "yacl/utils/serializer.h"
#include "yacl/utils/serializer_adapter.h"

/* submodules */
#include "yacl/crypto/rand/entropy_source/entropy_source.h"

namespace yacl::crypto {

// -------------------------------------------
// Sync Drbg (Experimental, s-DRBG)
// -------------------------------------------
//
// DRBG: Deterministic Random Bit Generator
//
// Syncable Drbg can be seen as an extension of standard DRBG (NIST-800-90A),
// with the additional support for "sync" functionality. It allows the user
// to grab the internal state of an existing s-drbg instance, and then pass
// this internal state to init a new s-drbg instance or reconfig an existing
// s-drbg. As the result, two s-drbg will behave exactly the same.
//
// Security considerations: As in NIST-800-90A rev1. section 8.5 DRBG Mechanism
// Boundaries, "A DRBG mechanism's functions may be contained within a single
// device, or may be distributed across multiple devices. Therefore the correct
// way of considering DRBG mechanism boundary is the combination of all s-drbgs
// having the same internal state.
//
// Within a DRBG mechanism boundary,
//
// 1. The DRBG internal state and the operation of the DRBG mechanism functions
// shall only be affected according to the DRBG mechanism specification.
//
// 2. The DRBG internal state shall exist solely within the DRBG mechanism
// boundary. The internal state shall not be accessible by non-DRBG functions or
// other instantiations of that DRBG or other DRBGs.
//
// 3. Information about secret parts of the DRBG internal state and intermediate
// values in computations involving these secret parts shall not affect any
// information that leaves the DRBG mechanism boundary, except as specified for
// the DRBG pseudorandom bit outputs.
//
//              +--------+  secure channel  +--------+
//              | s-DRBG | <==============> | s-DRBG |
//              +--------+  internal state  +--------+
//
// NOTE: all s-DRBGs should "jointly" re-init their internal state after certain
// rounds, or if necessary.
//
// NOTE: SyncDrbg does not provide full security guarantee of prediction
// resistance
//
// NOTE: SyncDrbg is supposed to be thread-safe with blocked sync

// currently, this implementation uses hash drbg.
// TODO: benchmark difference between hash drbg and ctr drgb
class SyncDrbg {
 public:
  // define general types
  using HashDrbgCtx =
      openssl::internal::TyHelper<HASH_DRBG_CTX, hash_drbg_ctx_free>;

  // Instantiate Sync Drbg.
  //
  // For parameter choices, see NIST-SP800-90A-rev1 Table 2, Definitions for
  // Hash-based DRBG mechanisms, column SHA-256 and SHA-512/256. The size of
  // both nonce and personal_string should not exceed 2^35 bits (2^32 bytes).
  explicit SyncDrbg() : SyncDrbg(nullptr, nullptr) {}
  explicit SyncDrbg(ByteContainerView nonce, ByteContainerView personal_string);

  // create drbg from existing context
  explicit SyncDrbg(HashDrbgCtx&& ctx) : ctx_(std::move(ctx)) {}  // move
  explicit SyncDrbg(const HashDrbgCtx& ctx);                      // copy

  // copy constructor
  SyncDrbg(SyncDrbg& other) : SyncDrbg(other.ctx_) {}
  SyncDrbg(SyncDrbg&& other) noexcept : SyncDrbg(std::move(other.ctx_)) {}

  // Destructor
  ~SyncDrbg() = default;

  // Fill the output with generated randomness. The size of additional_data
  // should not exceed 2^35 bits (2^32 bytes). This function would return 1 for
  // successful filling buf with len randomness, and 0 for failure.
  //
  // NOTE: By design, `Fill` fails silently if the drbg is in the syncing
  // process.
  int Fill(char* buf, size_t len) const noexcept {
    return Fill(buf, len, nullptr);
  }

  int Fill(char* buf, size_t len,
           ByteContainerView additional_data) const noexcept;

  // Renew the internal state of this drbg.
  //
  // This function will break its connection with other synced drbgs. SyncDrbg
  // need to reseed after a certain rounds. By default, this process happens
  // automatically when you call the function `Fill(...), and a log message will
  // appear when reseed happens.
  //
  // NOTE: you need to manually call sync all drbg states again, if reseed
  // happens.
  void Reseed() const { Reseed(nullptr); }
  void Reseed(ByteContainerView additional_data) const;

  // Fork this SyncDrbg, the internal states of the two instance stay same and
  // independent to each other
  SyncDrbg Fork() const { return SyncDrbg(ctx_); }

  // Sync function (this op is blocked)
  void SendState(const std::shared_ptr<link::Context>& lctx, size_t recv_rank);

  // Sync function (this op is blocked)
  void RecvState(const std::shared_ptr<link::Context>& lctx, size_t send_rank);

 private:
  // Drbg-context related variables, types and functions
  //
  // NOTE: Drbg context is stored as a smart pointer, therefore a const SyncDrbg
  // instance may also change its internal states after `Fill` is called.
  // However, a const SyncDrbg is by design not allowed to SendState or
  // RecvState
  //
  HashDrbgCtx ctx_ = HashDrbgCtx(hash_drbg_ctx_new());  // default void init

  // Handle multi-thread case, `Fill` should not be called during the sync
  // process.
  bool sync_flag_ = false;
  std::mutex sync_mutex_;

  Buffer serialize_hash_drbg_ctx();
  void deserialize_hash_drbg_ctx(Buffer&& buf);
};

}  // namespace yacl::crypto
