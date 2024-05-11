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

#include "yacl/kernel/svole_kernel.h"

#include <memory>
#include <variant>
#include <vector>

#include "yacl/base/byte_container_view.h"
#include "yacl/base/exception.h"
#include "yacl/crypto/tools/common.h"
#include "yacl/crypto/tools/ro.h"
#include "yacl/kernel/algorithms/silent_vole.h"
#include "yacl/link/context.h"
#include "yacl/utils/thread_pool.h"

namespace yacl::crypto {

namespace {
inline std::vector<std::shared_ptr<link::Context>> SetupLink(
    const std::shared_ptr<link::Context>& lctx, int threads) {
  std::vector<std::shared_ptr<link::Context>> out_threads(threads);
  for (int i = 0; i < threads; ++i) {
    out_threads[i] = lctx->Spawn();
  }
  return out_threads;
}

}  // namespace

void SVoleKernel::init(const std::shared_ptr<link::Context>& lctx,
                       CodeType code) {
  if (role_ == Role::Sender) {
    core_ = SilentVoleSender(code, false);

    // run the one-time setup (the result is cached into impl)
    std::get<SilentVoleSender>(core_).OneTimeSetup(lctx);
  } else {
    core_ = SilentVoleReceiver(code, false);

    // run the one-time setup (the result is cached into impl)
    std::get<SilentVoleReceiver>(core_).OneTimeSetup(lctx);
  }
  inited_ = true;
}

void SVoleKernel::eval(const std::shared_ptr<link::Context>& lctx,
                       uint128_t* out_delta, absl::Span<uint128_t> out_c) {
  YACL_ENFORCE(inited_);
  YACL_ENFORCE(std::holds_alternative<SilentVoleSender>(core_));
  std::get<SilentVoleSender>(core_).SfSend(lctx, out_c);
  *out_delta = std::get<SilentVoleSender>(core_).GetDelta();
}

void SVoleKernel::eval(const std::shared_ptr<link::Context>& lctx,
                       absl::Span<uint64_t> out_a,
                       absl::Span<uint128_t> out_b) {
  YACL_ENFORCE(inited_);
  YACL_ENFORCE(std::holds_alternative<SilentVoleReceiver>(core_));
  std::get<SilentVoleReceiver>(core_).SfRecv(lctx, out_a, out_b);
}

void SVoleKernel::eval_multithread(const std::shared_ptr<link::Context>& lctx,
                                   uint128_t* out_delta,
                                   absl::Span<uint128_t> out_c, int threads) {
  YACL_ENFORCE(inited_);
  YACL_ENFORCE(std::holds_alternative<SilentVoleSender>(core_));
  YACL_ENFORCE(threads >= 1);

  const size_t iter_size = out_c.size() / threads;
  const size_t last_size = out_c.size() - iter_size * (threads - 1);

  std::vector<absl::Span<uint128_t>> tl_c(threads); /*thread-local c spans*/
  for (int i = 0; i < threads - 1; ++i) {
    tl_c[i] = out_c.subspan(iter_size * i, iter_size);
  }
  tl_c[threads - 1] = out_c.subspan(iter_size * (threads - 1), last_size);

  uint128_t shared_seed = SyncSeedSend(lctx);
  *out_delta = std::get<SilentVoleSender>(core_).GetDelta();

  auto lctx_tl = SetupLink(lctx, threads); /* thread-local link */
  ThreadPool pool(threads);                // the destructor joins all threads
  auto task = [&](size_t i) {
    auto tl_seed = RandomOracle::GetDefault().Gen<uint64_t>(
        ByteContainerView(&shared_seed, sizeof(shared_seed)), i);
    auto tl_core = core_;
    std::get<SilentVoleSender>(tl_core).SetOTCounter(tl_seed);
    std::get<SilentVoleSender>(tl_core).SfSend(lctx_tl[i], tl_c[i]);
  };
  for (int i = 0; i < threads; ++i) {
    pool.Submit(task, i);
  }

  // the destructor of thread-pool joins all threads
}

void SVoleKernel::eval_multithread(const std::shared_ptr<link::Context>& lctx,
                                   absl::Span<uint64_t> out_a,
                                   absl::Span<uint128_t> out_b, int threads) {
  YACL_ENFORCE(inited_);
  YACL_ENFORCE(std::holds_alternative<SilentVoleReceiver>(core_));
  YACL_ENFORCE(out_a.size() == out_b.size());
  YACL_ENFORCE(threads >= 1);

  const size_t iter_size = out_a.size() / threads;
  const size_t last_size = out_a.size() - iter_size * (threads - 1);

  std::vector<absl::Span<uint64_t>> tl_a(threads);  /*thread-local a spans*/
  std::vector<absl::Span<uint128_t>> tl_b(threads); /*thread-local b spans*/
  for (int i = 0; i < threads - 1; ++i) {
    tl_a[i] = out_a.subspan(iter_size * i, iter_size);
    tl_b[i] = out_b.subspan(iter_size * i, iter_size);
  }
  tl_a[threads - 1] = out_a.subspan(iter_size * (threads - 1), last_size);
  tl_b[threads - 1] = out_b.subspan(iter_size * (threads - 1), last_size);

  uint128_t shared_seed = SyncSeedRecv(lctx);

  auto lctx_tl = SetupLink(lctx, threads); /* thread-local link */
  ThreadPool pool(threads);
  auto task = [&](size_t i) {
    auto tl_seed = RandomOracle::GetDefault().Gen<uint64_t>(
        ByteContainerView(&shared_seed, sizeof(shared_seed)), i);
    auto tl_core = core_;
    std::get<SilentVoleReceiver>(tl_core).SetOTCounter(tl_seed);
    std::get<SilentVoleReceiver>(tl_core).SfRecv(lctx_tl[i], tl_a[i], tl_b[i]);
  };
  for (int i = 0; i < threads; ++i) {
    pool.Submit(task, i);
  }

  // the destructor of thread-pool joins all threads
}

void SVoleKernel::eval_streaming(const std::shared_ptr<link::Context>& lctx,
                                 uint128_t* out_delta,
                                 absl::Span<uint128_t> out_c, int threads,
                                 int step_size) {
  YACL_ENFORCE(inited_);
  const size_t step_num = (out_c.size() + step_size - 1) / step_size;
  for (size_t i = 0; i < step_num; ++i) {
    auto local_step_size = (i == ((size_t)step_num - 1))
                               ? out_c.size() - step_size * (step_num - 1)
                               : step_size;
    eval_multithread(lctx, out_delta,
                     out_c.subspan(step_size * (step_num - 1), local_step_size),
                     threads);
  }

  *out_delta = std::get<SilentVoleSender>(core_).GetDelta();
}

void SVoleKernel::eval_streaming(const std::shared_ptr<link::Context>& lctx,
                                 absl::Span<uint64_t> out_a,
                                 absl::Span<uint128_t> out_b, int threads,
                                 int step_size) {
  YACL_ENFORCE(inited_);
  YACL_ENFORCE(out_a.size() == out_b.size());
  const size_t step_num = (out_a.size() + step_size - 1) / step_size;
  for (size_t i = 0; i < step_num; ++i) {
    auto local_step_size = (i == ((size_t)step_num - 1))
                               ? out_a.size() - step_size * (step_num - 1)
                               : step_size;
    eval_multithread(lctx, out_a.subspan(step_size * i, local_step_size),
                     out_b.subspan(step_size * i, local_step_size), threads);
  }
}

}  // namespace yacl::crypto
