// Copyright 2023 Ant Group Co., Ltd.
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

#include "yacl/crypto/zkp/sigma.h"

#include "yacl/crypto/tools/ro.h"

namespace yacl::crypto {

SigmaProtocol::SigmaProtocol(SigmaType type,
                             const std::shared_ptr<EcGroup>& group,
                             uint128_t seed, HashToCurveStrategy strategy)
    : SigmaProtocol(GetSigmaConfig(type), group, seed, strategy) {}

SigmaProtocol::SigmaProtocol(const SigmaConfig& config,
                             const std::shared_ptr<EcGroup>& group,
                             uint128_t seed, HashToCurveStrategy strategy)
    : SigmaProtocol(config, group,
                    SigmaOWH::MakeGenerators(config, group, seed, strategy)) {}

SigmaProtocol::SigmaProtocol(SigmaType type,
                             const std::shared_ptr<EcGroup>& group,
                             const SigmaGenerator& generators)
    : SigmaProtocol(GetSigmaConfig(type), group, generators) {}

SigmaProtocol::SigmaProtocol(const SigmaConfig& config,
                             const std::shared_ptr<EcGroup>& group,
                             const SigmaGenerator& generators)
    : config_(config), group_ref_(group), generators_(generators) {
  CheckParms();
}

SigmaProtocol::SigmaProtocol(SigmaType type,
                             const std::shared_ptr<EcGroup>& group,
                             ByteContainerView serialized_generators)
    : SigmaProtocol(GetSigmaConfig(type), group, serialized_generators) {}

SigmaProtocol::SigmaProtocol(const SigmaConfig& config,
                             const std::shared_ptr<EcGroup>& group,
                             ByteContainerView serialized_generators)
    : config_(config), group_ref_(group) {
  CheckParms();
  const auto kGroupLen = static_cast<uint64_t>(
      group_ref_->SerializePoint(group_ref_->GetGenerator()).size());
  for (uint64_t i = 0; i < serialized_generators.size(); i++) {
    auto tmp = group_ref_->DeserializePoint(
        {serialized_generators.data() + kGroupLen * i, kGroupLen});
    YACL_ENFORCE(
        !group_ref_->IsInfinity(tmp),
        "Generator should not be 1(identity elements)=infinity in ECC group!");
    generators_.emplace_back(tmp);
  }
}

void SigmaProtocol::CheckParms() const {
  YACL_ENFORCE(config_.IsQualified());
  YACL_ENFORCE(group_ref_->GetFieldType() == FieldType::Prime,
               "ECC-based Sigma proof systems should be implemented over "
               "prime-order groups!");
  switch (config_.type) {
    case SigmaType::Dlog:
    case SigmaType::Pedersen:
    case SigmaType::Representation:
    case SigmaType::SeveralDlog:
    case SigmaType::DlogEq:
    case SigmaType::SeveralDlogEq:
    case SigmaType::DHTripple:
      break;
    default:
      YACL_THROW(
          "yacl/zkp/sigma only supports Dlog, Pedersen, Representation, "
          "SeveralDlog, DlogEq, SeveralDlogEq, DHTripple types now!");
  }
}

SigmaStatement SigmaProtocol::ToStatement(const Witness& witness) const {
  return SigmaOWH::ToStatement(config_, group_ref_, generators_, witness);
}

SigmaStatement SigmaProtocol::RandStm(const Witness& rnd_witness) const {
  return ToStatement(rnd_witness);
}

SigmaProof SigmaProtocol::Prove(const Witness& witness,
                                const Witness& rnd_witness,
                                const Challenge& challenge) const {
  return Prove(config_, witness, rnd_witness, challenge,
               group_ref_->GetOrder());
}

bool SigmaProtocol::Verify(const SigmaStatement& statement,
                           const SigmaStatement& rnd_statement,
                           const Challenge& challenge,
                           const SigmaProof& proof) const {
  YACL_ENFORCE(statement.size() == config_.num_statement &&
               rnd_statement.size() == config_.num_statement);

  auto p_stm = ToStatement(proof);

  // num_statement means the number of statements should be checked
  for (size_t i = 0; i < config_.num_statement; i++) {
    if (!group_ref_->PointEqual(
            VerifyOp(group_ref_, statement[i], p_stm[i], challenge),
            rnd_statement[i])) {
      return false;
    }
  }
  return true;
}

SigmaBatchProof SigmaProtocol::ProveBatchable(
    const SigmaStatement& statement, const std::vector<MPInt>& witness,
    const std::vector<MPInt>& rnd_witness, ByteContainerView other_info) const {
  SigmaBatchProof ret_proof;
  // compute first message : rnd_statement
  ret_proof.rnd_statement = ToStatement(rnd_witness);
  // get challenge: RO(generators||statement||rnd_statement||other_info)
  MPInt challenge =
      GenChallenge(generators_, statement, ret_proof.rnd_statement, other_info);
  // compute second message : proof
  ret_proof.proof = Prove(witness, rnd_witness, challenge);

  return ret_proof;
}

bool SigmaProtocol::VerifyBatchable(const SigmaStatement& statement,
                                    const SigmaBatchProof& proof,
                                    ByteContainerView other_info) const {
  MPInt challenge =
      GenChallenge(generators_, statement, proof.rnd_statement, other_info);
  return Verify(statement, proof.rnd_statement, challenge, proof.proof);
}

SigmaShortProof SigmaProtocol::ProveCompact(
    const SigmaStatement& statement, const std::vector<MPInt>& witness,
    const std::vector<MPInt>& rnd_witness, ByteContainerView other_info) const {
  SigmaShortProof ret_proof;
  std::vector<EcPoint> rnd_statement;

  rnd_statement = ToStatement(rnd_witness);
  // get challenge: RO(generators||statement||rnd_statement||other_info)
  ret_proof.challenge =
      GenChallenge(generators_, statement, rnd_statement, other_info);
  ret_proof.proof = Prove(witness, rnd_witness, ret_proof.challenge);

  return ret_proof;
}

bool SigmaProtocol::VerifyCompact(const std::vector<EcPoint>& statement,
                                  const SigmaShortProof& proof,
                                  ByteContainerView other_info) const {
  YACL_ENFORCE(statement.size() == config_.num_statement);

  // Check if we could re-generate a same challenge by
  //   generators||statement||rnd_statement||other_info
  auto p_stm = ToStatement(proof.proof);
  SigmaStatement rnd_stm;
  // Compute rnd_statement
  for (uint32_t i = 0; i < config_.num_statement; i++) {
    rnd_stm.emplace_back(
        VerifyOp(group_ref_, statement[i], p_stm[i], proof.challenge));
  }
  // compute challenge
  MPInt challenge = GenChallenge(generators_, statement, rnd_stm, other_info);
  return challenge == proof.challenge;
}

Witness SigmaProtocol::GenRandomWitness() const {
  Witness ret;
  for (size_t i = 0; i < config_.num_rnd_witness; i++) {
    MPInt temp;
    MPInt::RandomLtN(group_ref_->GetOrder(), &temp);
    ret.emplace_back(temp);
  }
  return ret;
}

SigmaGenerator SigmaProtocol::GetGenerators() const { return generators_; }

Buffer SigmaProtocol::GeneratorsSerialize() const {
  auto g0_buf = group_ref_->SerializePoint(generators_[0]);
  const auto kGroupLen = static_cast<uint64_t>(g0_buf.size());
  Buffer buf(kGroupLen * generators_.size());
  std::memset(buf.data(), 0, buf.size());
  for (uint64_t i = 1; i < generators_.size(); i++) {
    Buffer temp{buf.data<uint8_t>() + i * kGroupLen, kGroupLen, [](void*) {}};
    group_ref_->SerializePoint(generators_[i], &temp);
  }
  return buf;
}

Challenge SigmaProtocol::GenChallenge() const {
  Challenge ret;
  MPInt::RandomLtN(group_ref_->GetOrder(), &ret);
  return ret;
}

MPInt SigmaProtocol::GenChallenge(const SigmaGenerator& generators,
                                  const std::vector<EcPoint>& statement,
                                  const std::vector<EcPoint>& rnd_statement,
                                  ByteContainerView other_info) const {
  return GenChallenge(group_ref_, generators, statement, rnd_statement,
                      other_info, config_.ro_type);
}

MPInt SigmaProtocol::GenChallenge(const std::shared_ptr<EcGroup>& group,
                                  const SigmaGenerator& generators,
                                  const std::vector<EcPoint>& statement,
                                  const std::vector<EcPoint>& rnd_statement,
                                  ByteContainerView other_info,
                                  HashAlgorithm ro_type) {
  auto order = group->GetOrder();
  RandomOracle ro(ro_type, (order.BitCount() + 7) / 8);
  std::string buf_str;

  for (uint32_t i = 0; i < generators.size(); i++) {
    buf_str.append(group->SerializePoint(generators[i]));
  }
  for (uint32_t i = 0; i < statement.size(); i++) {
    buf_str.append(group->SerializePoint(statement[i]));
  }
  for (uint32_t i = 0; i < rnd_statement.size(); i++) {
    buf_str.append(group->SerializePoint(rnd_statement[i]));
  }
  buf_str.append(other_info);

  // RO(gens||statements||rnd_statements||other_info)
  auto out = ro.Gen(buf_str);

  MPInt ret;
  ret.FromMagBytes(out);
  return ret % order;
}

MPInt SigmaProtocol::ProofOp(const MPInt& witness, const MPInt& rnd_witness,
                             const Challenge& challenge, const MPInt& order) {
  return rnd_witness.SubMod(challenge.MulMod(witness, order), order);
}

SigmaProof SigmaProtocol::Prove(const SigmaConfig& config,
                                const Witness& witness,
                                const Witness& rnd_witness,
                                const Challenge& challenge,
                                const MPInt& order) {
  YACL_ENFORCE(witness.size() == config.num_witness);
  YACL_ENFORCE(rnd_witness.size() == config.num_rnd_witness);

  SigmaProof proofs;
  // witness size = n
  for (size_t i = 0; i < config.num_witness; i++) {
    proofs.emplace_back(ProofOp(witness[i], rnd_witness[i], challenge, order));
  }
  return proofs;
}

EcPoint SigmaProtocol::VerifyOp(const std::shared_ptr<EcGroup>& group,
                                const EcPoint& stm, const EcPoint& proof_stm,
                                const Challenge& challenge) {
  auto ret = group->Mul(stm, challenge);
  group->AddInplace(&ret, proof_stm);
  return ret;
}

}  // namespace yacl::crypto
