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

#include "yacl/crypto/experimental/threshold_ecdsa/protocol/sign.h"

#include "yacl/crypto/experimental/threshold_ecdsa/common/errors.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/commitment.h"

namespace tecdsa::proto {
namespace {

constexpr char kSignPhase1CommitDomain[] = "GG2019/sign/phase1";

}  // namespace

SignParty::SignParty(SignConfig cfg)
    : cfg_(std::move(cfg)),
      peers_(BuildPeers(cfg_.participants, cfg_.self_id)),
      message_scalar_(Scalar::FromBigEndianModQ(cfg_.msg32)) {
  ValidateParticipantsOrThrow(cfg_.participants, cfg_.self_id, "SignParty");
  if (cfg_.msg32.size() != 32) {
    TECDSA_THROW_ARGUMENT("msg32 must be exactly 32 bytes for SignParty");
  }
  if (cfg_.local_key_share.x_i.value() == 0) {
    TECDSA_THROW_ARGUMENT("local x_i share must be non-zero");
  }
  if (cfg_.local_key_share.paillier == nullptr) {
    TECDSA_THROW_ARGUMENT("local Paillier provider must be present");
  }

  for (PartyIndex party : cfg_.participants) {
    if (!cfg_.public_keygen_data.all_X_i.contains(party) ||
        !cfg_.public_keygen_data.all_paillier_public.contains(party) ||
        !cfg_.public_keygen_data.all_aux_rsa_params.contains(party) ||
        !cfg_.public_keygen_data.all_square_free_proofs.contains(party) ||
        !cfg_.public_keygen_data.all_aux_param_proofs.contains(party)) {
      TECDSA_THROW_ARGUMENT("public keygen data is missing participant data");
    }

    const auto& paillier_public =
        cfg_.public_keygen_data.all_paillier_public.at(party);
    const auto& aux_params = cfg_.public_keygen_data.all_aux_rsa_params.at(party);
    const auto& square_free_proof =
        cfg_.public_keygen_data.all_square_free_proofs.at(party);
    const auto& aux_proof =
        cfg_.public_keygen_data.all_aux_param_proofs.at(party);

    ValidatePaillierPublicKeyOrThrow(paillier_public);
    if (!ValidateAuxRsaParams(aux_params)) {
      TECDSA_THROW_ARGUMENT("public aux RSA parameters are invalid");
    }

    const StrictProofVerifierContext context =
        BuildProofContext(cfg_.keygen_session_id, party);
    if (!VerifySquareFreeProofGmr98(paillier_public.n, square_free_proof,
                                    context)) {
      TECDSA_THROW_ARGUMENT("square-free proof verification failed");
    }
    if (!VerifyAuxRsaParamProofStrict(aux_params, aux_proof, context)) {
      TECDSA_THROW_ARGUMENT("aux parameter proof verification failed");
    }
  }

  const auto self_pk_it =
      cfg_.public_keygen_data.all_paillier_public.find(cfg_.self_id);
  if (self_pk_it == cfg_.public_keygen_data.all_paillier_public.end()) {
    TECDSA_THROW_ARGUMENT("missing self Paillier public key");
  }
  if (self_pk_it->second.n != cfg_.local_key_share.paillier->modulus_n()) {
    TECDSA_THROW_ARGUMENT(
        "self Paillier public key does not match local provider");
  }

  const auto self_x_it = cfg_.public_keygen_data.all_X_i.find(cfg_.self_id);
  if (self_x_it == cfg_.public_keygen_data.all_X_i.end()) {
    TECDSA_THROW_ARGUMENT("missing self X_i in public keygen data");
  }
  if (self_x_it->second != cfg_.local_key_share.X_i) {
    TECDSA_THROW_ARGUMENT("self X_i does not match local key share");
  }
}

SignRound1Msg SignParty::MakeRound1() {
  if (round1_.has_value()) {
    return *round1_;
  }

  local_k_i_ = RandomNonZeroScalar();
  local_gamma_i_ = RandomNonZeroScalar();
  local_Gamma_i_ = ECPoint::GeneratorMultiply(local_gamma_i_);
  const Bytes gamma_bytes = local_Gamma_i_.ToCompressedBytes();
  const CommitmentResult commitment =
      CommitMessage(kSignPhase1CommitDomain, gamma_bytes);
  local_round1_randomness_ = commitment.randomness;
  round1_ = SignRound1Msg{
      .commitment = commitment.commitment,
  };
  return *round1_;
}

}  // namespace tecdsa::proto
