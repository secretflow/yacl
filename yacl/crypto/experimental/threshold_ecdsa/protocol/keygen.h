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

#include <memory>
#include <optional>
#include <vector>

#include "yacl/crypto/experimental/threshold_ecdsa/protocol/messages.h"
#include "yacl/crypto/experimental/threshold_ecdsa/protocol/proto_common.h"

namespace tecdsa::proto {

struct KeygenConfig {
  Bytes session_id;
  PartyIndex self_id = 0;
  std::vector<PartyIndex> participants;
  uint32_t threshold = 1;
  uint32_t paillier_modulus_bits = 2048;
  uint32_t aux_rsa_modulus_bits = 2048;
};

class KeygenParty {
 public:
  explicit KeygenParty(KeygenConfig cfg);

  const KeygenConfig& config() const;

  KeygenRound1Msg MakeRound1();
  KeygenRound2Out MakeRound2(const PeerMap<KeygenRound1Msg>& peer_round1);
  KeygenRound3Msg MakeRound3(
      const PeerMap<KeygenRound2Broadcast>& peer_round2,
      const PeerMap<Scalar>& shares_for_self);
  KeygenOutput Finalize(const PeerMap<KeygenRound3Msg>& peer_round3);

 private:
  void EnsureLocalPolynomialPrepared();
  void EnsureLocalPaillierPrepared();
  void EnsureLocalProofsPrepared();
  bool VerifyDealerShareForSelf(PartyIndex dealer,
                                const KeygenRound2Broadcast& round2,
                                const Scalar& share) const;

  KeygenConfig cfg_;
  std::vector<PartyIndex> peers_;

  std::vector<Scalar> local_poly_coefficients_;
  PeerMap<Scalar> local_shares_;

  std::shared_ptr<PaillierProvider> local_paillier_;
  PaillierPublicKey local_paillier_public_;
  AuxRsaParams local_aux_rsa_params_;
  SquareFreeProof local_square_free_proof_;
  AuxRsaParamProof local_aux_param_proof_;

  ECPoint local_y_i_;
  Bytes local_commitment_;
  Bytes local_open_randomness_;
  std::vector<ECPoint> local_vss_commitments_;

  PeerMap<Bytes> all_phase1_commitments_;
  PeerMap<PaillierPublicKey> all_paillier_public_;
  PeerMap<AuxRsaParams> all_aux_rsa_params_;
  PeerMap<AuxRsaParamProof> all_aux_param_proofs_;

  Scalar local_x_i_;
  ECPoint aggregated_y_;

  std::optional<KeygenRound1Msg> round1_;
  std::optional<KeygenRound2Out> round2_;
  std::optional<KeygenRound3Msg> round3_;
  std::optional<KeygenOutput> output_;
};

}  // namespace tecdsa::proto
