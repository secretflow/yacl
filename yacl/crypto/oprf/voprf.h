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

#include <algorithm>
#include <cstring>
#include <memory>

#include "yacl/base/buffer.h"
#include "yacl/base/byte_container_view.h"
#include "yacl/base/exception.h"
#include "yacl/crypto/ecc/ec_point.h"
#include "yacl/crypto/hash/ssl_hash.h"
#include "yacl/crypto/oprf/oprf_ctx.h"
#include "yacl/math/mpint/mp_int.h"

namespace yacl::crypto {

struct Proof {
  math::MPInt c;
  math::MPInt s;
};

// RFC 9497: verifiable oblivious pseudorandom function (OPRF) using prime-order
// groups
//
// Client(input, pkS)          <----- pkS -----               Server(skS)
//   -------------------------------------------------------------------
//   blind, blindedElement = Blind(input)
//
//                              blindedElement
//                                ---------->
//
//                     evaluatedElement, proof = BlindEvaluate(skS, pkS,
//                                                       blindedElement)
//
//                          evaluatedElement, proof
//                                <----------
//
//   output = Finalize(input, blind, evaluatedElement
//                     blinedeElement, pkS, proof)

class VOprfServer {
 public:
  // Default constructor (with null OprfCtx)
  VOprfServer() = default;

  // Construct VOprfServer from OprfConfig
  explicit VOprfServer(const OprfConfig& config)
      : ctx_(std::make_shared<OprfCtx>(config)) {
    GenKeyPair();
  }

  explicit VOprfServer(const OprfConfig& config,
                       const std::array<char, 32> seed, const std::string& info)
      : ctx_(std::make_shared<OprfCtx>(config)) {
    DeriveKeyPair(seed, info);
  }

  // Construct VOprfServer from Existing OprfCtx (implicitly copied)
  explicit VOprfServer(const std::shared_ptr<OprfCtx>& ctx) : ctx_(ctx) {
    GenKeyPair();
  }

  // Construct VOprfServer from Existing OprfCtx (explicitly moved)
  explicit VOprfServer(std::shared_ptr<OprfCtx>&& ctx) : ctx_(std::move(ctx)) {
    GenKeyPair();
  }

  // Setup VOprfServer context, the new OprfCtx would overwrite the previous
  // OprfCtx, but previous OprfCtx may not be fully released from memory.
  void SetupCtx(const OprfConfig& config) {
    ctx_ = std::make_shared<OprfCtx>(config);
    GenKeyPair();
  }

  // fixme:
  // does not suupport batch,
  // for ecc does not provide an identity element
  // Compute the composite values for ec points m and z (fast)
  void ComputeCompositesFast(const std::vector<EcPoint>& blinded_element,
                             const std::vector<EcPoint>& evaluated_element,
                             EcPoint* m, EcPoint* z) {
    const std::string kPhaseStr = "Composite";

    auto* const ec = ctx_->BorrowEcGroup();

    // number of batched elements
    YACL_ENFORCE_EQ(blinded_element.size(), evaluated_element.size(),
                    "number of batched elements mismatch");
    int n = blinded_element.size();

    auto bm = ec->SerializePoint(pk_s_);
    std::string seedDST = "Seed-" + ctx_->GetContextString();

    Buffer seed_buf(2 + bm.size() + 2 + seedDST.size());
    char* seed_p = seed_buf.data<char>();

    std::memcpy(seed_p, crypto::I2OSP(bm.size(), 2).data(), 2);
    seed_p += 2;

    std::memcpy(seed_p, bm.data(), bm.size());
    seed_p += bm.size();

    std::memcpy(seed_p, crypto::I2OSP(seedDST.size(), 2).data(), 2);
    seed_p += 2;

    std::memcpy(seed_p, seedDST.data(), seedDST.size());

    auto seed =
        SslHash(ctx_->GetHashAlgorithm()).Update(seed_buf).CumulativeHash();

    // batch execution
    // temporary GetZero()
    // m = G - G = 0
    *m = ec->GetGenerator();
    *m = ec->Sub(*m, *m);
    for (int i = 0; i < n; ++i) {
      auto c_i = ec->SerializePoint(blinded_element[i]);
      auto d_i = ec->SerializePoint(evaluated_element[i]);

      Buffer composite_transcript(2 + seed.size() + 2 + 2 + c_i.size() + 2 +
                                  d_i.size() + kPhaseStr.size());
      char* composite_p = composite_transcript.data<char>();

      std::memcpy(composite_p, crypto::I2OSP(seed.size(), 2).data(), 2);
      composite_p += 2;

      std::memcpy(composite_p, seed.data(), seed.size());
      composite_p += seed.size();

      std::memcpy(composite_p, crypto::I2OSP(i, 2).data(), 2);
      composite_p += 2;

      std::memcpy(composite_p, crypto::I2OSP(c_i.size(), 2).data(), 2);
      composite_p += 2;

      std::memcpy(composite_p, c_i.data(), c_i.size());
      composite_p += c_i.size();

      std::memcpy(composite_p, crypto::I2OSP(d_i.size(), 2).data(), 2);
      composite_p += 2;

      std::memcpy(composite_p, d_i.data(), d_i.size());
      composite_p += d_i.size();

      // final step: copy phase string
      std::memcpy(composite_p, kPhaseStr.data(), kPhaseStr.size());

      auto scalar_i = ctx_->HashToScalar(composite_transcript);
      // M = di * C[i] + M
      *m = ec->Add(*m, ec->Mul(blinded_element[i], scalar_i));
    }
    // Z = k * M
    *z = ec->Mul(*m, sk_s_);
  }

  void GenerateProof(const std::vector<EcPoint>& blinded_element,
                     const std::vector<EcPoint>& evaluated_element, Proof* out,
                     const math::MPInt& randomness = 0_mp) {
    const std::string kPhaseStr = "Challenge";

    auto* const ec = ctx_->BorrowEcGroup();

    EcPoint m;
    EcPoint z;
    ComputeCompositesFast(blinded_element, evaluated_element, &m, &z);

    math::MPInt r;
    if (randomness.IsZero()) {
      math::MPInt::RandomLtN(ec->GetOrder(), &r);
    } else {
      r = randomness;
    }

    EcPoint t2 = ec->Mul(ec->GetGenerator(), r);
    EcPoint t3 = ec->Mul(m, r);

    auto bm = ec->SerializePoint(pk_s_);
    auto a0 = ec->SerializePoint(m);
    auto a1 = ec->SerializePoint(z);
    auto a2 = ec->SerializePoint(t2);
    auto a3 = ec->SerializePoint(t3);

    Buffer challenge_transcript(2 + bm.size() + 2 + a0.size() + 2 + a1.size() +
                                2 + a2.size() + 2 + a3.size() +
                                kPhaseStr.size());
    char* challenge_p = challenge_transcript.data<char>();

    std::memcpy(challenge_p, crypto::I2OSP(bm.size(), 2).data(), 2);
    challenge_p += 2;

    std::memcpy(challenge_p, bm.data(), bm.size());
    challenge_p += bm.size();

    std::memcpy(challenge_p, crypto::I2OSP(a0.size(), 2).data(), 2);
    challenge_p += 2;

    std::memcpy(challenge_p, a0.data(), a0.size());
    challenge_p += a0.size();

    std::memcpy(challenge_p, crypto::I2OSP(a1.size(), 2).data(), 2);
    challenge_p += 2;

    std::memcpy(challenge_p, a1.data(), a1.size());
    challenge_p += a1.size();

    std::memcpy(challenge_p, crypto::I2OSP(a2.size(), 2).data(), 2);
    challenge_p += 2;

    std::memcpy(challenge_p, a2.data(), a2.size());
    challenge_p += a2.size();

    std::memcpy(challenge_p, crypto::I2OSP(a3.size(), 2).data(), 2);
    challenge_p += 2;

    std::memcpy(challenge_p, a3.data(), a3.size());
    challenge_p += a3.size();

    // final step: copy phase string
    std::memcpy(challenge_p, kPhaseStr.data(), kPhaseStr.size());

    math::MPInt c = ctx_->HashToScalar(challenge_transcript);
    math::MPInt s = r - c * sk_s_;
    s = s.Mod(ec->GetOrder());

    out->c = c;
    out->s = s;
  }

  // in: skS, pkS, blindedElement
  // out: evaluatedElement, proof
  void BlindEvaluate(const EcPoint& blinded_element, EcPoint* evaluated_element,
                     Proof* proof, const math::MPInt& randomness = 0_mp) {
    YACL_ENFORCE(ctx_ != nullptr);
    YACL_ENFORCE(evaluated_element != nullptr);

    auto* const ec = ctx_->BorrowEcGroup();
    *evaluated_element = ec->Mul(blinded_element, sk_s_);

    auto blinded_elements = std::vector<EcPoint>{blinded_element};
    auto evaluated_elements = std::vector<EcPoint>{*evaluated_element};

    if (randomness.IsZero()) {
      GenerateProof(blinded_elements, evaluated_elements, proof);
    } else {
      GenerateProof(blinded_elements, evaluated_elements, proof, randomness);
    }
  }

  // Refresh the internally stored blind to a random value. You need to setup
  // OprfCtx before calling GenKeyPair()
  void GenKeyPair() {
    YACL_ENFORCE(ctx_ != nullptr);  // make sure context is setup
    std::tie(sk_s_, pk_s_) = ctx_->GenKeyPair();
  }

  void DeriveKeyPair(std::array<char, 32> seed, const std::string& info) {
    YACL_ENFORCE(ctx_ != nullptr);  // make sure context is setup
    std::tie(sk_s_, pk_s_) = ctx_->DeriveKeyPair(seed, info);
  }

  // Clear the internally stored blind value to zero
  void ClearBlind() { sk_s_ = 0_mp; }

  // Transfer the public key to the client
  EcPoint GetPKS() const { return pk_s_; }

 private:
  // NOTE oprf ctx may be reused by different oprf instance
  std::shared_ptr<OprfCtx> ctx_;

  math::MPInt sk_s_;
  EcPoint pk_s_;
};

class VOprfClient {
 public:
  // Default constructor (with null OprfCtx)
  VOprfClient() = default;

  // Construct VOprfClient from OprfConfig
  explicit VOprfClient(const OprfConfig& config)
      : ctx_(std::make_shared<OprfCtx>(config)) {
    RefreshBlind();
  }

  explicit VOprfClient(const OprfConfig& config, math::MPInt blindness)
      : ctx_(std::make_shared<OprfCtx>(config)) {
    blind_ = std::move(blindness);
  }

  // Construct VOprfClient from Existing OprfCtx (implicitly copied)
  explicit VOprfClient(const std::shared_ptr<OprfCtx>& ctx) : ctx_(ctx) {
    RefreshBlind();
  }

  // Construct VOprfClient from Existing OprfCtx (explicitly moved)
  explicit VOprfClient(std::shared_ptr<OprfCtx>&& ctx) : ctx_(std::move(ctx)) {
    RefreshBlind();
  }

  // Setup VOprfClient context, the new OprfCtx would overwrite the previous
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

    EcPoint in_point = ctx_->HashToGroup(in);

    *out = ec->Mul(in_point, blind_);
  }

  // Compute the composite values for ec points m and z (fast)
  void ComputeComposites(const std::vector<EcPoint>& blinded_element,
                         const std::vector<EcPoint>& evaluated_element,
                         EcPoint* m, EcPoint* z) {
    const std::string kPhaseStr = "Composite";

    auto* const ec = ctx_->BorrowEcGroup();

    // number of batched elements
    YACL_ENFORCE_EQ(blinded_element.size(), evaluated_element.size(),
                    "number of batched elements mismatch");
    int n = blinded_element.size();

    auto bm = ec->SerializePoint(pk_s_);
    std::string seedDST = "Seed-" + ctx_->GetContextString();

    Buffer seed_buf(2 + bm.size() + 2 + seedDST.size());
    char* seed_p = seed_buf.data<char>();

    std::memcpy(seed_p, crypto::I2OSP(bm.size(), 2).data(), 2);
    seed_p += 2;

    std::memcpy(seed_p, bm.data(), bm.size());
    seed_p += bm.size();

    std::memcpy(seed_p, crypto::I2OSP(seedDST.size(), 2).data(), 2);
    seed_p += 2;

    std::memcpy(seed_p, seedDST.data(), seedDST.size());

    auto seed =
        SslHash(ctx_->GetHashAlgorithm()).Update(seed_buf).CumulativeHash();

    // temporary GetZero()
    // m = G - G = 0
    *m = ec->GetGenerator();
    *m = ec->Sub(*m, *m);
    // z = G - G = 0
    *z = ec->GetGenerator();
    *z = ec->Sub(*z, *z);
    for (int i = 0; i < n; ++i) {
      auto c_i = ec->SerializePoint(blinded_element[i]);
      auto d_i = ec->SerializePoint(evaluated_element[i]);

      Buffer composite_transcript(2 + seed.size() + 2 + 2 + c_i.size() + 2 +
                                  d_i.size() + kPhaseStr.size());
      char* composite_p = composite_transcript.data<char>();

      std::memcpy(composite_p, crypto::I2OSP(seed.size(), 2).data(), 2);
      composite_p += 2;

      std::memcpy(composite_p, seed.data(), seed.size());
      composite_p += seed.size();

      std::memcpy(composite_p, crypto::I2OSP(i, 2).data(), 2);
      composite_p += 2;

      std::memcpy(composite_p, crypto::I2OSP(c_i.size(), 2).data(), 2);
      composite_p += 2;

      std::memcpy(composite_p, c_i.data(), c_i.size());
      composite_p += c_i.size();

      std::memcpy(composite_p, crypto::I2OSP(d_i.size(), 2).data(), 2);
      composite_p += 2;

      std::memcpy(composite_p, d_i.data(), d_i.size());
      composite_p += d_i.size();

      // final step: copy phase string
      std::memcpy(composite_p, kPhaseStr.data(), kPhaseStr.size());

      auto scalar_i = ctx_->HashToScalar(composite_transcript);

      // M = di * C[i] + M
      *m = ec->Add(*m, ec->Mul(blinded_element[i], scalar_i));
      // Z = di * D[i] + Z
      *z = ec->Add(*z, ec->Mul(evaluated_element[i], scalar_i));
    }
  }

  // Verify that the evaluated element is computed via server's sk_s_
  bool VerifyProof(const std::vector<EcPoint>& blinded_element,
                   const std::vector<EcPoint>& evaluated_element,
                   const Proof* proof) {
    const std::string kPhaseStr = "Challenge";

    auto* const ec = ctx_->BorrowEcGroup();

    EcPoint m;
    EcPoint z;
    ComputeComposites(blinded_element, evaluated_element, &m, &z);

    EcPoint t2 = ec->Add(ec->Mul(ec->GetGenerator(), proof->s),
                         ec->Mul(pk_s_, proof->c));
    EcPoint t3 = ec->Add(ec->Mul(m, proof->s), ec->Mul(z, proof->c));

    auto bm = ec->SerializePoint(pk_s_);
    auto a0 = ec->SerializePoint(m);
    auto a1 = ec->SerializePoint(z);
    auto a2 = ec->SerializePoint(t2);
    auto a3 = ec->SerializePoint(t3);

    Buffer challenge_transcript(2 + bm.size() + 2 + a0.size() + 2 + a1.size() +
                                2 + a2.size() + 2 + a3.size() +
                                kPhaseStr.size());
    char* challenge_p = challenge_transcript.data<char>();

    std::memcpy(challenge_p, crypto::I2OSP(bm.size(), 2).data(), 2);
    challenge_p += 2;

    std::memcpy(challenge_p, bm.data(), bm.size());
    challenge_p += bm.size();

    std::memcpy(challenge_p, crypto::I2OSP(a0.size(), 2).data(), 2);
    challenge_p += 2;

    std::memcpy(challenge_p, a0.data(), a0.size());
    challenge_p += a0.size();

    std::memcpy(challenge_p, crypto::I2OSP(a1.size(), 2).data(), 2);
    challenge_p += 2;

    std::memcpy(challenge_p, a1.data(), a1.size());
    challenge_p += a1.size();

    std::memcpy(challenge_p, crypto::I2OSP(a2.size(), 2).data(), 2);
    challenge_p += 2;

    std::memcpy(challenge_p, a2.data(), a2.size());
    challenge_p += a2.size();

    std::memcpy(challenge_p, crypto::I2OSP(a3.size(), 2).data(), 2);
    challenge_p += 2;

    std::memcpy(challenge_p, a3.data(), a3.size());
    challenge_p += a3.size();

    // final step: copy phase string
    std::memcpy(challenge_p, kPhaseStr.data(), kPhaseStr.size());

    auto expected_c = ctx_->HashToScalar(challenge_transcript);

    return (proof->c - expected_c).IsZero();
  }

  std::vector<uint8_t> Finalize(const EcPoint& evaluated_element,
                                const EcPoint& blinded_element,
                                // const Proof*,
                                const Proof* proof,
                                const std::string& private_input = "") {
    YACL_ENFORCE(ctx_ != nullptr);  // make sure context is setup

    auto* const ec = ctx_->BorrowEcGroup();

    auto blinded_elements = std::vector<EcPoint>{blinded_element};
    auto evaluated_elements = std::vector<EcPoint>{evaluated_element};

    YACL_ENFORCE(VerifyProof(blinded_elements, evaluated_elements, proof));

    // blind_inv = 1 / blind
    if (blind_inv_ == 0_mp) {
      MPInt::InvertMod(blind_, ec->GetOrder(), &blind_inv_);
    }

    // FIXME https://www.rfc-editor.org/rfc/rfc9496#section-4.3.2
    auto point_buf = ec->SerializePoint(ec->Mul(evaluated_element, blind_inv_));

    const std::string kPhaseStr = "Finalize";
    Buffer hash_buf(2 + private_input.size() + 2 + point_buf.size() +
                    kPhaseStr.size());
    char* p = hash_buf.data<char>();

    // copy len of private input
    YACL_ENFORCE(private_input.size() <= (1 << 16));
    std::memcpy(p, crypto::I2OSP(private_input.size(), 2).data(), 2);
    p += 2;

    // copy private_input
    std::memcpy(p, private_input.data(), private_input.size());
    p += private_input.size();

    // copy len of point_buf
    YACL_ENFORCE(point_buf.size() <= (1 << 16));
    std::memcpy(p, crypto::I2OSP(point_buf.size(), 2).data(), 2);
    p += 2;

    // copy point_buf
    std::memcpy(p, point_buf.data(), point_buf.size());
    p += point_buf.size();

    // final step: copy phase string
    std::memcpy(p, kPhaseStr.data(), kPhaseStr.size());

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

  void ReceivePKS(const EcPoint& pks) {
    YACL_ENFORCE(ctx_ != nullptr);  // make sure context is setup
    pk_s_ = pks;
  }

 private:
  // NOTE oprf ctx may be reused by different oprf instance
  std::shared_ptr<OprfCtx> ctx_;

  // Security-related values
  math::MPInt blind_;
  math::MPInt blind_inv_;

  // pkS received from the server during setup
  EcPoint pk_s_;
};

}  // namespace yacl::crypto
