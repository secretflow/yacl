// Copyright 2025 @yangjucai.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

#include <cstdint>
#include <memory>
#include <vector>

#include "yacl/base/buffer.h"
#include "yacl/base/exception.h"
#include "yacl/crypto/ecc/ec_point.h"
#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/crypto/experimental/zkp/bulletproofs/errors.h"
#include "yacl/crypto/experimental/zkp/bulletproofs/generators.h"
#include "yacl/crypto/experimental/zkp/bulletproofs/ipa/inner_product_proof.h"
#include "yacl/crypto/experimental/zkp/bulletproofs/simple_transcript.h"
#include "yacl/crypto/experimental/zkp/bulletproofs/util.h"
#include "yacl/math/mpint/mp_int.h"

namespace examples::zkp {

class RangeProof {
 public:
  // Default constructors and assignment operators
  RangeProof() = default;

  // Constructor matching the struct fields.
  RangeProof(const yacl::crypto::EcPoint A, const yacl::crypto::EcPoint S,
             const yacl::crypto::EcPoint T_1, const yacl::crypto::EcPoint T_2,
             const yacl::math::MPInt t_x, const yacl::math::MPInt t_x_blinding,
             const yacl::math::MPInt e_blinding, InnerProductProof ipp_proof);

  // Creates a rangeproof for a single value.
  static Result<std::pair<RangeProof, yacl::crypto::EcPoint>> ProveSingle(
      std::shared_ptr<SimpleTranscript> transcript,
      const std::shared_ptr<yacl::crypto::EcGroup>& curve,
      const std::shared_ptr<const BulletproofGens>& bp_gens,
      const std::shared_ptr<const PedersenGens>& pc_gens, uint64_t v,
      const yacl::math::MPInt& v_blinding, size_t n);

  // Verifies a rangeproof for a single value commitment.
  bool VerifySingle(std::shared_ptr<SimpleTranscript> transcript,
                    const std::shared_ptr<yacl::crypto::EcGroup>& curve,
                    const std::shared_ptr<const BulletproofGens>& bp_gens,
                    const std::shared_ptr<const PedersenGens>& pc_gens,
                    const yacl::crypto::EcPoint& V, size_t n) const;

  // Creates an aggregated rangeproof for multiple values.
  static Result<std::pair<RangeProof, std::vector<yacl::crypto::EcPoint>>>
  ProveMultiple(std::shared_ptr<SimpleTranscript> transcript,
                const std::shared_ptr<yacl::crypto::EcGroup>& curve,
                const std::shared_ptr<const BulletproofGens>& bp_gens,
                const std::shared_ptr<const PedersenGens>& pc_gens,
                const std::vector<uint64_t>& values,
                const std::vector<yacl::math::MPInt>& blindings, size_t n);

  // Verifies an aggregated rangeproof for multiple value commitments.
  bool VerifyMultiple(
      std::shared_ptr<SimpleTranscript> transcript,
      const std::shared_ptr<yacl::crypto::EcGroup>& curve,
      const std::shared_ptr<const BulletproofGens>& bp_gens,
      const std::shared_ptr<const PedersenGens>& pc_gens,
      const std::vector<yacl::crypto::EcPoint>& value_commitments,
      size_t n) const;

  // --- Serialization/Deserialization ---
  yacl::Buffer ToBytes(
      const std::shared_ptr<yacl::crypto::EcGroup>& curve) const;

  static RangeProof FromBytes(
      const std::shared_ptr<yacl::crypto::EcGroup>& curve,
      const yacl::ByteContainerView& bytes);

  const yacl::crypto::EcPoint& GetA() const { return A_; }
  const yacl::crypto::EcPoint& GetS() const { return S_; }
  const yacl::crypto::EcPoint& GetT1() const { return T_1_; }
  const yacl::crypto::EcPoint& GetT2() const { return T_2_; }
  const yacl::math::MPInt& GetTx() const { return t_x_; }
  const yacl::math::MPInt& GetTxBlinding() const { return t_x_blinding_; }
  const yacl::math::MPInt& GetEBlinding() const { return e_blinding_; }

  // Static helper to compute delta for aggregated proofs
  static yacl::math::MPInt Delta(
      size_t n, size_t m, const yacl::math::MPInt& y,
      const yacl::math::MPInt& z,
      const std::shared_ptr<yacl::crypto::EcGroup>& curve);

 private:
  yacl::crypto::EcPoint A_;
  yacl::crypto::EcPoint S_;
  yacl::crypto::EcPoint T_1_;
  yacl::crypto::EcPoint T_2_;
  yacl::math::MPInt t_x_;
  yacl::math::MPInt t_x_blinding_;
  yacl::math::MPInt e_blinding_;
  InnerProductProof ipp_proof_;
};

}  // namespace examples::zkp