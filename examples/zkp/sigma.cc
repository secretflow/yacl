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

#include "examples/zkp/sigma.h"

#include "yacl/crypto/tools/ro.h"
#include "yacl/utils/parallel.h"

namespace examples::zkp {

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
                             yacl::ByteContainerView serialized_generators)
    : SigmaProtocol(GetSigmaConfig(type), group, serialized_generators) {}

SigmaProtocol::SigmaProtocol(const SigmaConfig& config,
                             const std::shared_ptr<EcGroup>& group,
                             yacl::ByteContainerView serialized_generators)
    : config_(config), group_ref_(group) {
  CheckParms();
  const auto kGroupLen = group_ref_->GetSerializeLength();
  YACL_ENFORCE(serialized_generators.size() % kGroupLen == 0);
  const auto n = serialized_generators.size() / kGroupLen;
  for (uint64_t i = 0; i < n; i++) {
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
    const std::vector<MPInt>& rnd_witness,
    yacl::ByteContainerView other_info) const {
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
                                    yacl::ByteContainerView other_info) const {
  MPInt challenge =
      GenChallenge(generators_, statement, proof.rnd_statement, other_info);
  return Verify(statement, proof.rnd_statement, challenge, proof.proof);
}

SigmaShortProof SigmaProtocol::ProveCompact(
    const SigmaStatement& statement, const std::vector<MPInt>& witness,
    const std::vector<MPInt>& rnd_witness,
    yacl::ByteContainerView other_info) const {
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
                                  yacl::ByteContainerView other_info) const {
  YACL_ENFORCE(statement.size() == config_.num_statement);

  // Check if we could re-generate a same challenge by
  //   generators||statement||rnd_statement||other_info
  auto p_stm = ToStatement(proof.proof);
  // Compute rnd_statement
  auto rnd_stm = VerifyOp(group_ref_, statement, p_stm, proof.challenge);
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

yacl::Buffer SigmaProtocol::GeneratorsSerialize() const {
  const auto kGroupLen = group_ref_->GetSerializeLength();
  yacl::Buffer buf(kGroupLen * generators_.size());
  std::memset(buf.data(), 0, buf.size());
  for (uint64_t i = 0; i < generators_.size(); i++) {
    group_ref_->SerializePoint(generators_[i],
                               buf.data<uint8_t>() + i * kGroupLen, kGroupLen);
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
                                  yacl::ByteContainerView other_info) const {
  return GenChallenge(group_ref_, generators, statement, rnd_statement,
                      other_info, config_.ro_type, config_.point_format);
}

MPInt SigmaProtocol::GenChallenge(
    const std::shared_ptr<EcGroup>& group, yacl::ByteContainerView prefix,
    const SigmaGenerator& generators, const std::vector<EcPoint>& statement,
    const std::vector<EcPoint>& rnd_statement,
    yacl::ByteContainerView other_info, HashAlgorithm ro_type,
    PointOctetFormat point_format, yacl::Endian endianness) {
  auto order = group->GetOrder();
  RandomOracle ro(ro_type, (order.BitCount() + 7) / 8);
  std::string buf_str;
  if (!prefix.empty()) {
    buf_str.append(std::begin(prefix), std::end(prefix));
  }
  for (uint32_t i = 0; i < generators.size(); i++) {
    buf_str.append(group->SerializePoint(generators[i], point_format));
  }
  for (uint32_t i = 0; i < statement.size(); i++) {
    buf_str.append(group->SerializePoint(statement[i], point_format));
  }
  for (uint32_t i = 0; i < rnd_statement.size(); i++) {
    buf_str.append(group->SerializePoint(rnd_statement[i], point_format));
  }
  buf_str.append(other_info);

  // RO(prefix||gens||statements||rnd_statements||other_info)
  auto out = ro.Gen(buf_str);

  MPInt ret;
  ret.FromMagBytes(out, endianness);
  return ret % order;
}

SigmaProof SigmaProtocol::Prove(const SigmaConfig& config,
                                const Witness& witness,
                                const Witness& rnd_witness,
                                const Challenge& challenge,
                                const MPInt& order) {
  YACL_ENFORCE(witness.size() == config.num_witness);
  YACL_ENFORCE(rnd_witness.size() == config.num_rnd_witness);

  return ProofOp(witness, rnd_witness, challenge, order);
}

MPInt SigmaProtocol::ProofOp(const MPInt& witness, const MPInt& rnd_witness,
                             const Challenge& challenge, const MPInt& order) {
  return rnd_witness.SubMod(challenge.MulMod(witness, order), order);
}

std::vector<MPInt> SigmaProtocol::ProofOp(const std::vector<MPInt>& witness,
                                          const std::vector<MPInt>& rnd_witness,
                                          const Challenge& challenge,
                                          const MPInt& order) {
  YACL_ENFORCE(witness.size() == rnd_witness.size());
  std::vector<MPInt> result(witness.size());
  yacl::parallel_for(0, witness.size(), [&](int64_t beg, int64_t end) {
    for (auto i = beg; i < end; i++) {
      result[i] = (rnd_witness[i] - (challenge * witness[i] % order)) % order;
    }
  });
  return result;
}

EcPoint SigmaProtocol::VerifyOp(const std::shared_ptr<EcGroup>& group,
                                const EcPoint& stm, const EcPoint& proof_stm,
                                const Challenge& challenge) {
  auto ret = group->Mul(stm, challenge);
  group->AddInplace(&ret, proof_stm);
  return ret;
}

std::vector<EcPoint> SigmaProtocol::VerifyOp(
    const std::shared_ptr<EcGroup>& group, const std::vector<EcPoint>& stm,
    const std::vector<EcPoint>& proof_stm, const Challenge& challenge) {
  YACL_ENFORCE(proof_stm.size() == stm.size());

  std::vector<EcPoint> rtm(stm.size());
  yacl::parallel_for(0, stm.size(), [&](int64_t beg, int64_t end) {
    for (auto i = beg; i < end; i++) {
      rtm[i] = group->Add(group->Mul(stm[i], challenge), proof_stm[i]);
    }
  });
  return rtm;
}

}  // namespace examples::zkp
