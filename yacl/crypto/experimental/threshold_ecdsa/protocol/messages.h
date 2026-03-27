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
#include <memory>
#include <optional>
#include <unordered_map>
#include <vector>

#include "yacl/crypto/experimental/threshold_ecdsa/common/bytes.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/ec_point.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/paillier.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/scalar.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/strict_proofs.h"
#include "yacl/crypto/experimental/threshold_ecdsa/protocol/types.h"

namespace tecdsa::proto {

template <typename T>
using PeerMap = std::unordered_map<PartyIndex, T>;

struct SchnorrProof {
  ECPoint a;
  Scalar z;
};

struct VRelationProof {
  ECPoint alpha;
  Scalar t;
  Scalar u;
};

enum class MtaType : uint8_t {
  kTimesGamma = 1,
  kTimesW = 2,
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

struct KeygenRound1Msg {
  Bytes commitment;
  PaillierPublicKey paillier_public;
  AuxRsaParams aux_rsa_params;
  AuxRsaParamProof aux_param_proof;
};

struct KeygenRound2Broadcast {
  ECPoint y_i;
  Bytes randomness;
  std::vector<ECPoint> commitments;
};

struct KeygenRound2Out {
  KeygenRound2Broadcast broadcast;
  PeerMap<Scalar> shares_for_peers;
};

struct KeygenRound3Msg {
  ECPoint X_i;
  SchnorrProof proof;
  SquareFreeProof square_free_proof;
};

struct LocalKeyShare {
  Scalar x_i;
  ECPoint X_i;
  std::shared_ptr<PaillierProvider> paillier;
};

struct PublicKeygenData {
  ECPoint y;
  PeerMap<ECPoint> all_X_i;
  PeerMap<PaillierPublicKey> all_paillier_public;
  PeerMap<AuxRsaParams> all_aux_rsa_params;
  PeerMap<SquareFreeProof> all_square_free_proofs;
  PeerMap<AuxRsaParamProof> all_aux_param_proofs;
};

struct KeygenOutput {
  LocalKeyShare local_key_share;
  PublicKeygenData public_keygen_data;
};

struct SignRound1Msg {
  Bytes commitment;
};

struct SignRound2Request {
  PartyIndex from = 0;
  PartyIndex to = 0;
  MtaType type = MtaType::kTimesGamma;
  Bytes instance_id;
  BigInt c1 = BigInt(0);
  A1RangeProof a1_proof;
};

struct SignRound2Response {
  PartyIndex from = 0;
  PartyIndex to = 0;
  MtaType type = MtaType::kTimesGamma;
  Bytes instance_id;
  BigInt c2 = BigInt(0);
  std::optional<A2MtAwcProof> a2_proof;
  std::optional<A3MtAProof> a3_proof;
};

struct SignRound3Msg {
  Scalar delta_i;
};

struct SignRound4Msg {
  ECPoint gamma_i;
  Bytes randomness;
  SchnorrProof gamma_proof;
};

struct SignRound5AMsg {
  Bytes commitment;
};

struct SignRound5BMsg {
  ECPoint V_i;
  ECPoint A_i;
  Bytes randomness;
  SchnorrProof a_schnorr_proof;
  VRelationProof v_relation_proof;
};

struct SignRound5CMsg {
  Bytes commitment;
};

struct SignRound5DMsg {
  ECPoint U_i;
  ECPoint T_i;
  Bytes randomness;
};

struct Signature {
  Scalar r;
  Scalar s;
  ECPoint R;
};

}  // namespace tecdsa::proto
