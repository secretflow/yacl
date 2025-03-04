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

#include <memory>

#include "yacl/base/byte_container_view.h"
#include "yacl/crypto/ecc/ec_point.h"
#include "yacl/crypto/hash/ssl_hash.h"
#include "yacl/crypto/oprf/oprf_ctx.h"
#include "yacl/math/mpint/mp_int.h"

namespace yacl::crypto {

// RFC 9497: oblivious pseudorandom function (OPRF) using prime-order groups
//
// Client(input)                                        Server(skS)
//   -------------------------------------------------------------------
//   blind, blindedElement = Blind(input)
//
//                              blindedElement
//                                ---------->
//
//                 evaluatedElement = BlindEvaluate(skS, blindedElement)
//
//                              evaluatedElement
//                                <----------
//
//   output = Finalize(input, blind, evaluatedElement)

class OprfServer {
 public:
  // Default constructor (with null OprfCtx)
  OprfServer() = default;

  // Construct OprfServer from OprfConfig
  explicit OprfServer(const OprfConfig& config)
      : ctx_(std::make_shared<OprfCtx>(config)) {
    RefreshBlind();
  }

  // Construct OprfServer from Existing OprfCtx (implicitly copied)
  explicit OprfServer(const std::shared_ptr<OprfCtx>& ctx) : ctx_(ctx) {
    RefreshBlind();
  }

  // Construct OprfServer from Existing OprfCtx (explicitly moved)
  explicit OprfServer(std::shared_ptr<OprfCtx>&& ctx) : ctx_(std::move(ctx)) {
    RefreshBlind();
  }

  // Setup OprfServer context, the new OprfCtx would overwrite the previous
  // OprfCtx, but previous OprfCtx may not be fully released from memory.
  void SetupCtx(const OprfConfig& config) {
    ctx_ = std::make_shared<OprfCtx>(config);
    RefreshBlind();
  }

  void BlindEvaluate(const EcPoint& in, EcPoint* out) {
    YACL_ENFORCE(ctx_ != nullptr);  // make sure context is setup
    YACL_ENFORCE(out != nullptr);   // make sure out is not nullptr

    auto* const ec = ctx_->BorrowEcGroup();
    *out = ec->Mul(in, blind_);
  }

  // Refresh the internally stored blind to a random value. You need to setup
  // OprfCtx before calling RefreshBlind()
  void RefreshBlind() {
    YACL_ENFORCE(ctx_ != nullptr);  // make sure context is setup
    auto* const ec = ctx_->BorrowEcGroup();
    math::MPInt::RandomLtN(ec->GetOrder(), &blind_);
  }

  // Clear the internally stored blind value to zero
  void ClearBlind() { blind_ = 0_mp; }

 private:
  // NOTE oprf ctx may be reused by different oprf instance
  std::shared_ptr<OprfCtx> ctx_;

  // Security-related values
  math::MPInt blind_;
};

class OprfClient {
 public:
  // Default constructor (with null OprfCtx)
  OprfClient() = default;

  // Construct OprfClient from OprfConfig
  explicit OprfClient(const OprfConfig& config)
      : ctx_(std::make_shared<OprfCtx>(config)) {
    RefreshBlind();
  }

  // Construct OprfClient from Existing OprfCtx (implicitly copied)
  explicit OprfClient(const std::shared_ptr<OprfCtx>& ctx) : ctx_(ctx) {
    RefreshBlind();
  }

  // Construct OprfClient from Existing OprfCtx (explicitly moved)
  explicit OprfClient(std::shared_ptr<OprfCtx>&& ctx) : ctx_(std::move(ctx)) {
    RefreshBlind();
  }

  // Setup OprfClient context, the new OprfCtx would overwrite the previous
  // OprfCtx, but previous OprfCtx may not be fully released from memory.
  void SetupCtx(const OprfConfig& config) {
    ctx_ = std::make_shared<OprfCtx>(config);
    RefreshBlind();
  };

  // Hash to map and then blind the string
  void Blind(const std::string& in, EcPoint* out) {
    YACL_ENFORCE(ctx_ != nullptr);  // make sure context is setup
    YACL_ENFORCE(out != nullptr);   // make sure out is not nullptr

    auto* const ec = ctx_->BorrowEcGroup();
    EcPoint in_point = ec->HashToCurve(in);
    *out = ec->Mul(in_point, blind_);
  }

  std::vector<uint8_t> Finalize(const EcPoint& in,
                                const std::string& private_input = "") {
    YACL_ENFORCE(ctx_ != nullptr);  // make sure context is setup

    auto* const ec = ctx_->BorrowEcGroup();
    if (blind_inv_ == 0_mp) {
      MPInt::InvertMod(blind_, ec->GetOrder(), &blind_inv_);
    }

    // FIXME https://www.rfc-editor.org/rfc/rfc9496#section-4.3.2
    auto point_buf = ec->SerializePoint(ec->Mul(in, blind_inv_));

    const std::string kPhaseStr = "Finalize";
    Buffer hash_buf(2 + private_input.size() + 2 + point_buf.size() +
                    kPhaseStr.size());
    char* p = hash_buf.data<char>();

    // copy len of private input
    YACL_ENFORCE(private_input.size() <= (1 << 16));
    uint64_t len = private_input.size();
    std::memcpy(p, &len, 2);
    p += 2;

    // copy private_input
    snprintf(p, private_input.size(), "%s", private_input.data());
    p += private_input.size();

    // copy len of point_buf
    YACL_ENFORCE(point_buf.size() <= (1 << 16));
    len = point_buf.size();
    std::memcpy(p, &len, 2);
    p += 2;

    // copy point_buf
    std::memcpy(p, point_buf.data(), point_buf.size());
    p += point_buf.size();

    // final step: copy phase string
    snprintf(p, kPhaseStr.size(), "%s", kPhaseStr.data());

    // hash every thing in hash_buf
    return SslHash(ctx_->GetHashAlgorithm()).Update(hash_buf).CumulativeHash();
  }

  void RefreshBlind() {
    YACL_ENFORCE(ctx_ != nullptr);  // make sure context is setup
    auto* const ec = ctx_->BorrowEcGroup();
    math::MPInt::RandomLtN(ec->GetOrder(), &blind_);
  }

  // Clear the internally stored blind value to zero
  void ClearBlind() {
    blind_ = 0_mp;
    blind_inv_ = 0_mp;
  }

 private:
  // NOTE oprf ctx may be reused by different oprf instance
  std::shared_ptr<OprfCtx> ctx_;

  // Security-related values
  math::MPInt blind_;
  math::MPInt blind_inv_;
};

}  // namespace yacl::crypto
