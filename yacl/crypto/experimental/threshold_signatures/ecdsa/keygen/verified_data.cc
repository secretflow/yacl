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

#include "yacl/crypto/experimental/threshold_signatures/ecdsa/keygen/verified_data.h"

#include <string>
#include <utility>

#include "yacl/crypto/experimental/threshold_signatures/common/errors.h"
#include "yacl/crypto/experimental/threshold_signatures/core/paillier/aux_proofs.h"
#include "yacl/crypto/experimental/threshold_signatures/core/paillier/paper_aux_proofs.h"
#include "yacl/crypto/experimental/threshold_signatures/core/paillier/paillier.h"

namespace tecdsa::ecdsa::keygen {
namespace {

namespace paillier = tecdsa::core::paillier;

template <typename MapT>
void RequirePartyEntry(const MapT& map, PartyIndex party,
                       const char* field_name) {
  if (!map.contains(party)) {
    TECDSA_THROW_ARGUMENT(std::string("public keygen data missing ") +
                          field_name);
  }
}

}  // namespace

VerifiedPublicKeygenData VerifiedPublicKeygenData::Create(
    const PublicKeygenData& public_data, const Bytes& keygen_session_id,
    const core::ThresholdSuite& suite,
    const std::shared_ptr<const core::GroupContext>& group,
    std::span<const PartyIndex> participants, PartyIndex self_id,
    const LocalKeyShare& local_key_share) {
  for (PartyIndex party : participants) {
    RequirePartyEntry(public_data.all_X_i, party, "X_i");
    RequirePartyEntry(public_data.all_paillier_public, party,
                      "Paillier public key");
    RequirePartyEntry(public_data.all_aux_rsa_params, party,
                      "auxiliary RSA parameters");
    RequirePartyEntry(public_data.all_square_free_proofs, party,
                      "square-free proof");
    RequirePartyEntry(public_data.all_aux_param_proofs, party,
                      "aux parameter proof");

    const auto& paillier_public = public_data.all_paillier_public.at(party);
    const auto& aux_params = public_data.all_aux_rsa_params.at(party);
    const auto& square_free_proof =
        public_data.all_square_free_proofs.at(party);
    const auto& aux_param_proof = public_data.all_aux_param_proofs.at(party);

    paillier::ValidatePaillierPublicKeyOrThrow(paillier_public, group);
    if (!paillier::ValidateAuxRsaParams(aux_params)) {
      TECDSA_THROW_ARGUMENT("public aux RSA parameters are invalid");
    }

    const paillier::StrictProofVerifierContext proof_context =
        paillier::BuildProofContext(keygen_session_id, party, suite, group);
    if (!paillier::VerifySquareFreeProofGmr98(paillier_public.n,
                                              square_free_proof,
                                              proof_context)) {
      TECDSA_THROW_ARGUMENT("square-free proof verification failed");
    }
    if (!paillier::VerifyAuxCorrectFormProof(aux_params, aux_param_proof,
                                             proof_context)) {
      TECDSA_THROW_ARGUMENT("aux parameter proof verification failed");
    }
  }

  if (local_key_share.paillier == nullptr) {
    TECDSA_THROW_ARGUMENT("local Paillier provider must be present");
  }
  const auto self_pk_it = public_data.all_paillier_public.find(self_id);
  if (self_pk_it == public_data.all_paillier_public.end()) {
    TECDSA_THROW_ARGUMENT("missing self Paillier public key");
  }
  if (self_pk_it->second.n != local_key_share.paillier->modulus_n_bigint()) {
    TECDSA_THROW_ARGUMENT(
        "self Paillier public key does not match local provider");
  }

  const auto self_x_it = public_data.all_X_i.find(self_id);
  if (self_x_it == public_data.all_X_i.end()) {
    TECDSA_THROW_ARGUMENT("missing self X_i in public keygen data");
  }
  if (self_x_it->second != local_key_share.X_i) {
    TECDSA_THROW_ARGUMENT("self X_i does not match local key share");
  }

  return VerifiedPublicKeygenData(public_data);
}

const PublicKeygenData& VerifiedPublicKeygenData::raw() const {
  if (!initialized_) {
    TECDSA_THROW_LOGIC("verified public keygen data is not initialized");
  }
  return public_data_;
}

const PaillierPublicKey& VerifiedPublicKeygenData::PaillierOf(
    PartyIndex party) const {
  const auto it = raw().all_paillier_public.find(party);
  if (it == raw().all_paillier_public.end()) {
    TECDSA_THROW_LOGIC("missing verified Paillier public key");
  }
  return it->second;
}

const AuxRsaParams& VerifiedPublicKeygenData::AuxOf(PartyIndex party) const {
  const auto it = raw().all_aux_rsa_params.find(party);
  if (it == raw().all_aux_rsa_params.end()) {
    TECDSA_THROW_LOGIC("missing verified auxiliary parameters");
  }
  return it->second;
}

const ECPoint& VerifiedPublicKeygenData::XOf(PartyIndex party) const {
  const auto it = raw().all_X_i.find(party);
  if (it == raw().all_X_i.end()) {
    TECDSA_THROW_LOGIC("missing verified X_i");
  }
  return it->second;
}

}  // namespace tecdsa::ecdsa::keygen
