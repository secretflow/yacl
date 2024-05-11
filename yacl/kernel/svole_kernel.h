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

#include "yacl/kernel/kernel.h"

/* submodules */
#include "yacl/kernel/algorithms/silent_vole.h"
#include "yacl/kernel/code/silver_code.h"

namespace yacl::crypto {

// ---------------------
// Kernel: Subfield VOLE
// ---------------------
// c = a * delta + b
// - where a is in GF(2^64), delta, b, c are in GF(2^128)
// Sender receives: c, delta
// Receiver receives: a, b
class SVoleKernel : StreamKernel {
 public:
  enum class Role { Sender, Receiver };

  // constructor
  explicit SVoleKernel(Role role) : role_(role) {}

  // the one-time setup
  void init(const std::shared_ptr<link::Context>& lctx,
            CodeType code = CodeType::Silver11);

  // evaluate function for sender
  void eval(const std::shared_ptr<link::Context>& lctx, uint128_t* out_delta,
            absl::Span<uint128_t> out_c);
  void eval_multithread(const std::shared_ptr<link::Context>& lctx,
                        uint128_t* out_delta, absl::Span<uint128_t> out_c,
                        int threads);
  void eval_streaming(const std::shared_ptr<link::Context>& lctx,
                      uint128_t* out_delta, absl::Span<uint128_t> out_c,
                      int threads, int step_size);

  // evaluate function for receiver
  void eval(const std::shared_ptr<link::Context>& lctx,
            absl::Span<uint64_t> out_a, absl::Span<uint128_t> out_b);

  void eval_multithread(const std::shared_ptr<link::Context>& lctx,
                        absl::Span<uint64_t> out_a, absl::Span<uint128_t> out_b,
                        int threads);

  void eval_streaming(const std::shared_ptr<link::Context>& lctx,
                      absl::Span<uint64_t> out_a, absl::Span<uint128_t> out_b,
                      int threads, int step_size);

 private:
  // use config
  const Role role_; /* you should not change that after init */

  // kernel's internal status
  bool inited_ = false;
  using CoreTy =
      std::variant<std::monostate, SilentVoleSender, SilentVoleReceiver>;
  CoreTy core_;
};

}  // namespace yacl::crypto
