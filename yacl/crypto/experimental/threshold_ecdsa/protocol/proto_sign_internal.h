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

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "yacl/crypto/experimental/threshold_ecdsa/common/bytes.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/ec_point.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/scalar.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/strict_proofs.h"
#include "yacl/crypto/experimental/threshold_ecdsa/protocol/types.h"

namespace tecdsa::sign_internal {

inline constexpr size_t kCommitmentLen = 32;
inline constexpr size_t kMtaInstanceIdLen = 16;
inline constexpr char kPhase1CommitDomain[] = "GG2019/sign/phase1";
inline constexpr char kPhase5ACommitDomain[] = "GG2019/sign/phase5A";
inline constexpr char kPhase5CCommitDomain[] = "GG2019/sign/phase5C";

using AuxRsaParams = tecdsa::AuxRsaParams;

struct MtaProofContext {
  Bytes session_id;
  PartyIndex initiator_id = 0;
  PartyIndex responder_id = 0;
  Bytes mta_instance_id;
};

struct A1RangeProof {
  BigInt z = BigInt(0);
  BigInt u = BigInt(0);
  BigInt w = BigInt(0);
  BigInt s = BigInt(0);
  BigInt s1 = BigInt(0);
  BigInt s2 = BigInt(0);
};

struct A2MtAwcProof {
  ECPoint u;
  BigInt z = BigInt(0);
  BigInt z2 = BigInt(0);
  BigInt t = BigInt(0);
  BigInt v = BigInt(0);
  BigInt w = BigInt(0);
  BigInt s = BigInt(0);
  BigInt s1 = BigInt(0);
  BigInt s2 = BigInt(0);
  BigInt t1 = BigInt(0);
  BigInt t2 = BigInt(0);
};

struct A3MtAProof {
  BigInt z = BigInt(0);
  BigInt z2 = BigInt(0);
  BigInt t = BigInt(0);
  BigInt v = BigInt(0);
  BigInt w = BigInt(0);
  BigInt s = BigInt(0);
  BigInt s1 = BigInt(0);
  BigInt s2 = BigInt(0);
  BigInt t1 = BigInt(0);
  BigInt t2 = BigInt(0);
};

std::string BytesToKey(const Bytes& bytes);
std::string MakeResponderRequestKey(PartyIndex initiator, uint8_t type_code);
Bytes RandomMtaInstanceId();

BigInt RandomBelow(const BigInt& upper_exclusive);
BigInt SampleZnStar(const BigInt& modulus_n);
const BigInt& QPow5();
BigInt MulMod(const BigInt& lhs, const BigInt& rhs, const BigInt& modulus);
BigInt PowMod(const BigInt& base, const BigInt& exp, const BigInt& modulus);
std::optional<Scalar> InvertScalar(const Scalar& scalar);

A1RangeProof ProveA1Range(const MtaProofContext& ctx, const BigInt& n,
                          const AuxRsaParams& verifier_aux, const BigInt& c,
                          const BigInt& witness_m, const BigInt& witness_r);
bool VerifyA1Range(const MtaProofContext& ctx, const BigInt& n,
                   const AuxRsaParams& verifier_aux, const BigInt& c,
                   const A1RangeProof& proof);

A2MtAwcProof ProveA2MtAwc(const MtaProofContext& ctx, const BigInt& n,
                          const AuxRsaParams& verifier_aux, const BigInt& c1,
                          const BigInt& c2, const ECPoint& statement_x,
                          const BigInt& witness_x, const BigInt& witness_y,
                          const BigInt& witness_r);
bool VerifyA2MtAwc(const MtaProofContext& ctx, const BigInt& n,
                   const AuxRsaParams& verifier_aux, const BigInt& c1,
                   const BigInt& c2, const ECPoint& statement_x,
                   const A2MtAwcProof& proof);

A3MtAProof ProveA3MtA(const MtaProofContext& ctx, const BigInt& n,
                      const AuxRsaParams& verifier_aux, const BigInt& c1,
                      const BigInt& c2, const BigInt& witness_x,
                      const BigInt& witness_y, const BigInt& witness_r);
bool VerifyA3MtA(const MtaProofContext& ctx, const BigInt& n,
                 const AuxRsaParams& verifier_aux, const BigInt& c1,
                 const BigInt& c2, const A3MtAProof& proof);

Bytes SerializePointPair(const ECPoint& first, const ECPoint& second);
Scalar BuildVRelationChallenge(const Bytes& session_id, PartyIndex party_id,
                               const ECPoint& r_statement,
                               const ECPoint& v_statement,
                               const ECPoint& alpha);
ECPoint BuildRGeneratorLinearCombination(const ECPoint& r_base,
                                         const Scalar& r_multiplier,
                                         const Scalar& g_multiplier);

}  // namespace tecdsa::sign_internal
