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

#pragma once

#include <memory>
#include <variant>

#include "yacl/base/dynamic_bitset.h"
#include "yacl/kernel/algorithms/ot_store.h"
#include "yacl/kernel/kernel.h"

/* submodules */
#include "yacl/kernel/algorithms/base_ot.h"
#include "yacl/kernel/algorithms/ferret_ote.h"
#include "yacl/kernel/algorithms/softspoken_ote.h"
#include "yacl/secparam.h"

namespace yacl::crypto {

// --------------------------
// Kernel: Oblivious Transfer
// --------------------------
// OT kernel is an application-level API. The functionality of oblivious
// transfer could be seen as the following:
//
//           [sender]               [receiver]
//
//           m0 ----> +----------+ <---- b
//                    |    OT    |
//           m1 ----> +----------+ ----> mb
//
// where,
// - m0 is a uint128_t message
// - m1 is a uint128_t message
// - b is a single bit
// - mb is a uint128_t message, when b=0, mb=m0, when b=1, mb=m1.

class OtKernel : SingleThreadKernel {
 public:
  enum class Role { Sender, Receiver };

  enum class ExtAlgorithm {
    Ferret,      // default: softspoken + ferrret
    SoftSpoken,  // faster on LAN
    // IKNP,        // not recommended
    // KOS,         // not recommended
  };

  // constructor
  explicit OtKernel(Role role,
                    ExtAlgorithm ext_algorithm = ExtAlgorithm::Ferret)
      : role_(role), ext_algorithm_(ext_algorithm) {}

  // the one-time setup (base OT + extra)
  void init(const std::shared_ptr<link::Context>& lctx);

  // re-init this kernel, kernel behaves the same as self-destroy, and re-init a
  // new kernel, but refresh should be faster
  // void refresh();

  // ----------------------------------
  // Correlated OT, a.k.a. delta-ot
  // ----------------------------------
  // In the correlated ot case, the two messages received by the sender is
  // delta-correlated, which means m0 xor m1 = delta
  //
  // Note: all correlated ot instances are stored in *compact mode*
  // see: yacl/kernel/algorithms/ot_store.h
  void eval_cot_random_choice(const std::shared_ptr<link::Context>& lctx,
                              uint64_t ot_num,
                              /* compact mode */ OtSendStore* out);
  void eval_cot_random_choice(const std::shared_ptr<link::Context>& lctx,
                              uint64_t ot_num,
                              /* compact mode */ OtRecvStore* out);

  // TODO(@shanzhu): Add this feature
  // void cot_update_delta();  // update the delta of this ot kernel

  // -------------------------------
  // Random OT
  // -------------------------------
  // Random ot with random messages and random chocies, rot will first generate
  // *ot_num* cot instances, and then runs crhash (correlation-robust hash
  // function) in parallel for all the cot messages. Even though the output
  // ot_store of cot is compact, we use normal ot_store for rots.
  void eval_rot(const std::shared_ptr<link::Context>& lctx, uint64_t ot_num,
                /* normal mode */ OtSendStore* out);
  void eval_rot(const std::shared_ptr<link::Context>& lctx, uint64_t ot_num,
                /* normal mode */ OtRecvStore* out);

 private:
  // -------------------------------
  // Configurations for Kernel
  // -------------------------------
  const Role role_;  // receiver or sender

  // OT Extension algorithm
  const ExtAlgorithm ext_algorithm_ = ExtAlgorithm::Ferret;

  // -------------------------------//
  // Kernel Internal States
  // -------------------------------//

  // whether this kernel has been inited (e.g. one-time-setup)
  bool inited_ = false;

  // the underlying store type for internal cache
  using StoreTy = std::variant<std::monostate, OtRecvStore, OtSendStore>;
  StoreTy init_ot_cache_;  // ot cache from the init phase

  // the underlying core type for softspoken
  using SoftSpokenCoreTy = std::variant<std::monostate, SoftspokenOtExtSender,
                                        SoftspokenOtExtReceiver>;
  SoftSpokenCoreTy ss_core_;
};

}  // namespace yacl::crypto
