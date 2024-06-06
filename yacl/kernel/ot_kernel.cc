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

#include "yacl/kernel/ot_kernel.h"

#include <memory>
#include <variant>
#include <vector>

#include "yacl/base/byte_container_view.h"
#include "yacl/base/exception.h"
#include "yacl/crypto/rand/rand.h"
#include "yacl/crypto/tools/common.h"
#include "yacl/crypto/tools/ro.h"
#include "yacl/kernel/algorithms/base_ot.h"
#include "yacl/kernel/algorithms/ferret_ote.h"
#include "yacl/kernel/algorithms/ot_store.h"
#include "yacl/kernel/algorithms/softspoken_ote.h"
#include "yacl/link/context.h"
#include "yacl/secparam.h"
#include "yacl/utils/parallel.h"
#include "yacl/utils/thread_pool.h"

namespace yacl::crypto {

namespace {

constexpr uint32_t kBatchSize = 128;

using OtMsg = uint128_t;
using OtMsgPair = std::array<OtMsg, 2>;
using OtChoices = dynamic_bitset<uint128_t>;

// Inplace-conversion from cot to rot
void naive_cot2rot(const OtSendStore& cot_store, OtSendStore* rot_store) {
  YACL_ENFORCE(cot_store.Size() == rot_store->Size());     // size should match
  YACL_ENFORCE(cot_store.Type() == OtStoreType::Compact);  // compact mode
  YACL_ENFORCE(rot_store->Type() == OtStoreType::Normal);  // normal mode
  const uint32_t ot_num = cot_store.Size();  // warning: narrow conversion
  parallel_for(0, ot_num, 1, [&](uint64_t beg, uint64_t end) {
    for (uint64_t i = beg; i < end; ++i) {
      rot_store->SetNormalBlock(i, 0, CrHash_128(cot_store.GetBlock(i, 0)));
      rot_store->SetNormalBlock(i, 1, CrHash_128(cot_store.GetBlock(i, 1)));
    }
  });
}

// Inplace-conversion from cot to rot
void naive_cot2rot(const OtRecvStore& cot_store, OtRecvStore* rot_store) {
  const uint32_t ot_num = cot_store.Size();  // warning: narrow conversion
  YACL_ENFORCE(cot_store.Type() == OtStoreType::Compact);  // compact mode
  YACL_ENFORCE(rot_store->Type() == OtStoreType::Normal);  // normal mode
  auto choices = cot_store.CopyBitBuf();
  rot_store->SetBitBuf(choices);

  parallel_for(0, ot_num, 1, [&](uint64_t beg, uint64_t end) {
    for (uint64_t i = beg; i < end; ++i) {
      rot_store->SetBlock(i, CrHash_128(cot_store.GetBlock(i)));
    }
  });
}

// Conversion from cot to rot (OtStoreType == Normal)
[[maybe_unused]] void naive_rot2ot(
    const std::shared_ptr<yacl::link::Context>& lctx,
    const OtSendStore& ot_store, absl::Span<const OtMsgPair> msgpairs) {
  static_assert(kBatchSize % 128 == 0);  // batch size should be multiple of 128
  YACL_ENFORCE(ot_store.Type() == OtStoreType::Normal);
  YACL_ENFORCE(ot_store.Size() == msgpairs.size());
  const uint32_t ot_num = msgpairs.size();
  const uint32_t batch_num = (ot_num + kBatchSize - 1) / kBatchSize;

  dynamic_bitset<uint128_t> masked_choices(ot_num);
  auto buf = lctx->Recv(lctx->NextRank(), "");
  std::memcpy(masked_choices.data(), buf.data(), buf.size());

  // for each batch
  for (uint32_t i = 0; i < batch_num; ++i) {
    const uint32_t limit = std::min(kBatchSize, ot_num - i * kBatchSize);

    // generate masks for all msg pairs
    std::vector<OtMsgPair> batch_send(limit);
    for (uint32_t j = 0; j < limit; ++j) {
      auto idx = i * kBatchSize + j;
      // fmt::print("{} {}\n", idx, masked_choices.size());

      if (!masked_choices[idx]) {
        batch_send[j][0] = ot_store.GetBlock(idx, 0) ^ msgpairs[idx][0];
        batch_send[j][1] = ot_store.GetBlock(idx, 1) ^ msgpairs[idx][1];
      } else {
        batch_send[j][0] = ot_store.GetBlock(idx, 1) ^ msgpairs[idx][0];
        batch_send[j][1] = ot_store.GetBlock(idx, 0) ^ msgpairs[idx][1];
      }
    }

    lctx->SendAsync(
        lctx->NextRank(),
        ByteContainerView(batch_send.data(), sizeof(uint128_t) * limit * 2),
        "");
  }
}

[[maybe_unused]] void naive_rot2ot(
    const std::shared_ptr<yacl::link::Context>& lctx,
    const OtRecvStore& ot_store, const OtChoices& choices,
    absl::Span<OtMsg> out) {
  static_assert(kBatchSize % 128 == 0);  // batch size should be multiple of 128
  YACL_ENFORCE(ot_store.Type() == OtStoreType::Normal);
  YACL_ENFORCE(ot_store.Size() == choices.size());
  const uint32_t ot_num = ot_store.Size();
  const uint32_t batch_num = (ot_num + kBatchSize - 1) / kBatchSize;

  auto masked_choice = ot_store.CopyBitBuf() ^ choices;
  lctx->SendAsync(
      lctx->NextRank(),
      ByteContainerView(masked_choice.data(),
                        sizeof(uint128_t) * masked_choice.num_blocks()),
      "Sending masked choices");

  // for each batch
  for (uint32_t i = 0; i < batch_num; ++i) {
    const uint32_t limit = std::min(kBatchSize, ot_num - i * kBatchSize);

    // receive masked messages
    auto buf = lctx->Recv(lctx->NextRank(), "");
    std::vector<OtMsgPair> batch_recv(limit);
    std::memcpy(batch_recv.data(), buf.data(), buf.size());

    for (uint32_t j = 0; j < limit; ++j) {
      auto idx = i * kBatchSize + j;
      // fmt::print("{} {}\n", idx, choices.size());
      out[idx] = batch_recv[j][choices[idx]] ^ ot_store.GetBlock(idx);
    }
  }
}

}  // namespace

void OtKernel::init(const std::shared_ptr<link::Context>& lctx) {
  switch (ext_algorithm_) {
    case ExtAlgorithm::Ferret: {
      auto required_ot_num =
          FerretCotHelper(LpnParam::GetDefault(), LpnParam::GetDefault().n);

      // we use softspoken to init ferret ote
      OtKernel ss_ote_kernel(role_, ExtAlgorithm::SoftSpoken);
      ss_ote_kernel.init(lctx);
      if (role_ == Role::Sender) {
        init_ot_cache_ = OtSendStore(required_ot_num, OtStoreType::Compact);
        ss_ote_kernel.eval_cot_random_choice(
            lctx, required_ot_num, &std::get<OtSendStore>(init_ot_cache_));
      } else {
        init_ot_cache_ = OtRecvStore(required_ot_num, OtStoreType::Compact);
        ss_ote_kernel.eval_cot_random_choice(
            lctx, required_ot_num, &std::get<OtRecvStore>(init_ot_cache_));
      }
      break;
    }
    case ExtAlgorithm::SoftSpoken:
      if (role_ == Role::Sender) {
        ss_core_ = SoftspokenOtExtSender(2, 0, false, /* compact ot */ true);
        std::get<SoftspokenOtExtSender>(ss_core_).OneTimeSetup(lctx);
      } else {
        ss_core_ = SoftspokenOtExtReceiver(2, 0, false, /* compact ot */ true);
        std::get<SoftspokenOtExtReceiver>(ss_core_).OneTimeSetup(lctx);
      }
      break;
    default:
      YACL_THROW("Unsupported OT Extension Algorithm");
  }
  inited_ = true;
}

void OtKernel::eval_cot_random_choice(
    const std::shared_ptr<link::Context>& lctx, uint64_t ot_num,
    OtSendStore* out) {
  YACL_ENFORCE(ot_num == out->Size());  // size should match
  YACL_ENFORCE(!out->IsSliced());       // no slice
  YACL_ENFORCE(inited_);

  // the output ot store should be in compact mode
  YACL_ENFORCE(out->Type() == OtStoreType::Compact);

  switch (ext_algorithm_) {
    case ExtAlgorithm::Ferret: {
      // ferret ot sender needs OtSendStore
      YACL_ENFORCE(std::holds_alternative<OtSendStore>(init_ot_cache_));

      auto lpn_param = LpnParam::GetDefault();  // use default Lpn parameter
      *out = FerretOtExtSend(lctx, std::get<OtSendStore>(init_ot_cache_),
                             lpn_param, ot_num);
      break;
    }
    case ExtAlgorithm::SoftSpoken: {
      YACL_ENFORCE(std::holds_alternative<SoftspokenOtExtSender>(ss_core_));
      std::get<SoftspokenOtExtSender>(ss_core_).Send(lctx, out);
      break;
    }
    default:
      YACL_THROW("Unsupported OT Extension Algorithm");
  }
}

void OtKernel::eval_cot_random_choice(
    const std::shared_ptr<link::Context>& lctx, uint64_t ot_num,
    OtRecvStore* out) {
  YACL_ENFORCE(ot_num == out->Size());                // size should match
  YACL_ENFORCE(!out->IsSliced());                     // no slice
  YACL_ENFORCE(out->Type() == OtStoreType::Compact);  // compact mode
  YACL_ENFORCE(inited_);

  // the output ot store should be in compact mode
  YACL_ENFORCE(out->Type() == OtStoreType::Compact);

  switch (ext_algorithm_) {
    case ExtAlgorithm::Ferret: {
      // ferret ot sender needs OtRecvStore
      YACL_ENFORCE(std::holds_alternative<OtRecvStore>(init_ot_cache_));

      auto lpn_param = LpnParam::GetDefault();  // use default Lpn parameter
      *out = FerretOtExtRecv(lctx, std::get<OtRecvStore>(init_ot_cache_),
                             lpn_param, ot_num);
      break;
    }
    case ExtAlgorithm::SoftSpoken: {
      YACL_ENFORCE(std::holds_alternative<SoftspokenOtExtReceiver>(ss_core_));
      auto choices = SecureRandBits(ot_num);
      std::get<SoftspokenOtExtReceiver>(ss_core_).Recv(lctx, choices, out);
      break;
    }
    default:
      YACL_THROW("Unsupported OT Extension Algorithm");
  }
}

void OtKernel::eval_rot(const std::shared_ptr<link::Context>& lctx,
                        uint64_t ot_num, OtSendStore* out) {
  YACL_ENFORCE(ot_num == out->Size());               // size should match
  YACL_ENFORCE(!out->IsSliced());                    // no slice
  YACL_ENFORCE(out->Type() == OtStoreType::Normal);  // normal mode
  OtSendStore cot(ot_num, OtStoreType::Compact);
  eval_cot_random_choice(lctx, ot_num, &cot);
  naive_cot2rot(cot, out);
}

void OtKernel::eval_rot(const std::shared_ptr<link::Context>& lctx,
                        uint64_t ot_num, OtRecvStore* out) {
  YACL_ENFORCE(ot_num == out->Size());               // size should match
  YACL_ENFORCE(!out->IsSliced());                    // no slice
  YACL_ENFORCE(out->Type() == OtStoreType::Normal);  // normal mode
  OtRecvStore cot(ot_num, OtStoreType::Compact);
  eval_cot_random_choice(lctx, ot_num, &cot);
  naive_cot2rot(cot, out);
}

// void OtKernel::eval_rot(const std::shared_ptr<link::Context>& lctx,
//                         uint64_t ot_num, OtSendStore* out) {
//   eval_cot_random_choice(lctx, ot_num, out);
// }
// void OtKernel::eval_rot(const std::shared_ptr<link::Context>& lctx,
//                         uint64_t ot_num,
//                         /* random choice */ OtRecvStore* out) {}

}  // namespace yacl::crypto
