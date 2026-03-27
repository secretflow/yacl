// Copyright 2026 Ant Group Co., Ltd.
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

#include <cstdint>
#include <optional>
#include <span>

#include "yacl/crypto/experimental/threshold_ecdsa/common/bytes.h"
#include "yacl/crypto/experimental/threshold_ecdsa/protocol/types.h"
#include "yacl/math/mpint/mp_int.h"

namespace tecdsa {

using BigInt = yacl::math::MPInt;

struct StrictProofVerifierContext {
  Bytes session_id;
  std::optional<PartyIndex> prover_id;
  std::optional<PartyIndex> verifier_id;
};

struct AuxRsaParams {
  BigInt n_tilde = BigInt(0);
  BigInt h1 = BigInt(0);
  BigInt h2 = BigInt(0);
};

struct SquareFreeProof {
  Bytes blob;
};

struct AuxRsaParamProof {
  Bytes blob;
};

bool IsZnStarElement(const BigInt& value, const BigInt& modulus);
bool ValidateAuxRsaParams(const AuxRsaParams& params);
bool IsLikelySquareFreeModulus(const BigInt& modulus_n);

Bytes EncodeSquareFreeProof(const SquareFreeProof& proof);
SquareFreeProof DecodeSquareFreeProof(std::span<const uint8_t> encoded,
                                      size_t max_len = 16384);

Bytes EncodeAuxRsaParamProof(const AuxRsaParamProof& proof);
AuxRsaParamProof DecodeAuxRsaParamProof(std::span<const uint8_t> encoded,
                                        size_t max_len = 4096);

AuxRsaParams GenerateAuxRsaParams(uint32_t modulus_bits, PartyIndex party_id);

SquareFreeProof BuildSquareFreeProofGmr98(
    const BigInt& modulus_n, const BigInt& lambda_n,
    const StrictProofVerifierContext& context = {});
bool VerifySquareFreeProofGmr98(const BigInt& modulus_n,
                                const SquareFreeProof& proof,
                                const StrictProofVerifierContext& context = {});

AuxRsaParamProof BuildAuxRsaParamProofStrict(
    const AuxRsaParams& params, const StrictProofVerifierContext& context = {});
bool VerifyAuxRsaParamProofStrict(
    const AuxRsaParams& params, const AuxRsaParamProof& proof,
    const StrictProofVerifierContext& context = {});

}  // namespace tecdsa
