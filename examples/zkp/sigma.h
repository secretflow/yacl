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

#pragma once

#include "examples/zkp/sigma_config.h"
#include "examples/zkp/sigma_owh.h"

namespace examples::zkp {

using namespace yacl::crypto;
using yacl::math::MPInt;

// We abide an unifying view to implment the common Sigma-type zero-knowledge
// proof (ZKP) schemes, in which we view the ZKP schemes as proof of knowledge
// of a pre-image of a one-way group homomorphism(OWH) and a specific group
// homomorphism would determine a specific scheme [Mau09].
// In other words, the prover wants to convince the verifier that he knows the
// witness(pre-image) of the statement(OWH and the result of OWH taking input by
// the witness).
//
// Consider two groups (G, +), (H, *), a challenge space N and an one-way
// group homomorphism(f) G -> H : x -> z = f(x)
// -----------------------------------------------------------------
//          prover                        verifier
//  knows     x                            z=f(x)
//
//  RandStm:
//   k <-(random)- G
//   t = f(k)               t
//                  ----------------->  GenChallenge:
//                          c            challenge c <-(random)- N
//  Proof:          <-----------------
//   r = k + x^c            r
//                  ----------------->  Verify:
//                                       check if f(r) ?= t * z^c
// -----------------------------------------------------------------
//
// For example,
//   - if we take the group homomorphism [·]: x -> z as z=[x]=h^x, then the
//   proof system is the known Schnorr protocol [Sch89] for proving knowledge of
//   discrete logarithm problem.
//   - if we take the group homomorphism [·]: x,r -> z as z=[x,r]=h_1^x·h_2^r,
//   then the proof the known ZKP scheme for proving knowledge of opening value
//   of Pedersen commitment [Oka92].
//
// Note, we also provide non-interactive proof methods in two ways [KO21]:
//   - compact (proof contents: challenge, response)
//   - batchable form (proof contents: commitment, response)
//
// Papers:
//   - [Mau09] Unifying Zero-Knowledge Proofs of Knowledge
//   - [Sch89] Efficient signature generation by smart cards
//   - [Oka92] Provably Secure and Practical Identification Schemes and
//     Corresponding Signature Schemes,
//   - [KO21] Proposal: Σ-protocols,
//     https://docs.zkproof.org/pages/standards/accepted-workshop4/proposal-sigma.pdf
//
class SigmaProtocol {
 public:
  // seed, use to generate group generators by HashToCurve Method
  explicit SigmaProtocol(
      SigmaType type, const std::shared_ptr<EcGroup>& group,
      uint128_t seed = SecureRandU128(),
      HashToCurveStrategy strategy = HashToCurveStrategy::Autonomous);
  explicit SigmaProtocol(
      const SigmaConfig& config, const std::shared_ptr<EcGroup>& group,
      uint128_t seed = SecureRandU128(),
      HashToCurveStrategy strategy = HashToCurveStrategy::Autonomous);

  explicit SigmaProtocol(SigmaType type, const std::shared_ptr<EcGroup>& group,
                         const SigmaGenerator& generators);
  explicit SigmaProtocol(const SigmaConfig& config,
                         const std::shared_ptr<EcGroup>& group,
                         const SigmaGenerator& generators);

  explicit SigmaProtocol(SigmaType type, const std::shared_ptr<EcGroup>& group,
                         yacl::ByteContainerView serialized_generators);
  explicit SigmaProtocol(const SigmaConfig& config,
                         const std::shared_ptr<EcGroup>& group,
                         yacl::ByteContainerView serialized_generators);

  SigmaStatement ToStatement(const Witness& witness) const;

  //
  // 3-round Interactive version
  //
  // Round1: Prover, generate random statement
  // Start Interactive proof
  SigmaStatement RandStm(const Witness& rnd_witness) const;

  // Round2: Verifier, send a random challenge to prover, suggest use
  // GenChallenge()

  // round3: Prover, generate proof by witness, rnd_witness and challenge.
  SigmaProof Prove(const Witness& witness, const Witness& rnd_witness,
                   const Challenge& challenge) const;
  static SigmaProof Prove(const SigmaConfig& config, const Witness& witness,
                          const Witness& rnd_witness,
                          const Challenge& challenge, const MPInt& order);
  // round3: Verifier, verify the proof
  bool Verify(const SigmaStatement& statement,
              const SigmaStatement& rnd_statement, const Challenge& challenge,
              const SigmaProof& proof) const;

  //
  // Non-interactive version, Batchable
  //
  //  other_info for generation of challenge as H(...||other_info)
  //  rnd_witness is the same number of random stuffs for proof
  SigmaBatchProof ProveBatchable(const SigmaStatement& statement,
                                 const std::vector<MPInt>& witness,
                                 const std::vector<MPInt>& rnd_witness,
                                 yacl::ByteContainerView other_info = {}) const;
  bool VerifyBatchable(const SigmaStatement& statement,
                       const SigmaBatchProof& proof,
                       yacl::ByteContainerView other_info = {}) const;

  //
  // Non-interactive version, Compact
  //
  SigmaShortProof ProveCompact(const SigmaStatement& statement,
                               const std::vector<MPInt>& witness,
                               const std::vector<MPInt>& rnd_witness,
                               yacl::ByteContainerView other_info = {}) const;
  bool VerifyCompact(const std::vector<EcPoint>& statement,
                     const SigmaShortProof& proof,
                     yacl::ByteContainerView other_info = {}) const;

  //
  // Tool Functions
  //
  Challenge GenChallenge() const;
  Witness GenRandomWitness() const;
  SigmaGenerator GetGenerators() const;
  yacl::Buffer GeneratorsSerialize() const;

  // ro_type, the Random Oracle instance
  // point_format, Group Point Serialization Mode
  // endianness, Scalar Deserialization Mode to generate the final challenge
  // Return the challenge AS:
  // DeserScalar(endianness,
  //             RO(
  //                ro_type,
  //                prefix
  //                ||SerPoints(point_format, generators)
  //                ||SerPoints(point_format,statement)
  //                ||SerPoints(point_format, rnd_statement)
  //                ||other_info
  //                  )
  //            )
  static MPInt GenChallenge(
      const std::shared_ptr<EcGroup>& group, yacl::ByteContainerView prefix,
      const SigmaGenerator& generators, const std::vector<EcPoint>& statement,
      const std::vector<EcPoint>& rnd_statement,
      yacl::ByteContainerView other_info = {},
      HashAlgorithm ro_type = HashAlgorithm::BLAKE3,
      PointOctetFormat point_format = PointOctetFormat::Autonomous,
      yacl::Endian endianness = yacl::Endian::big);
  static MPInt GenChallenge(
      const std::shared_ptr<EcGroup>& group, const SigmaGenerator& generators,
      const std::vector<EcPoint>& statement,
      const std::vector<EcPoint>& rnd_statement,
      yacl::ByteContainerView other_info = {},
      HashAlgorithm ro_type = HashAlgorithm::BLAKE3,
      PointOctetFormat point_format = PointOctetFormat::Autonomous,
      yacl::Endian endianness = yacl::Endian::big) {
    return GenChallenge(group, "", generators, statement, rnd_statement,
                        other_info, ro_type, point_format, endianness);
  }
  static MPInt GenChallenge(
      const std::shared_ptr<EcGroup>& group, yacl::ByteContainerView prefix,
      const std::vector<EcPoint>& statement,
      yacl::ByteContainerView other_info = {},
      HashAlgorithm ro_type = HashAlgorithm::BLAKE3,
      PointOctetFormat point_format = PointOctetFormat::Autonomous,
      yacl::Endian endianness = yacl::Endian::big) {
    return GenChallenge(group, prefix, statement, {}, {}, other_info, ro_type,
                        point_format, endianness);
  }
  // rnd_witness - challenge * witness
  static MPInt ProofOp(const MPInt& witness, const MPInt& rnd_witness,
                       const Challenge& challenge, const MPInt& order);
  static std::vector<MPInt> ProofOp(const std::vector<MPInt>& witness,
                                    const std::vector<MPInt>& rnd_witness,
                                    const Challenge& challenge,
                                    const MPInt& order);
  // proof_stm( = g^proof) + statement * challenge
  static EcPoint VerifyOp(const std::shared_ptr<EcGroup>& group,
                          const EcPoint& stm, const EcPoint& proof_stm,
                          const Challenge& challenge);
  static std::vector<EcPoint> VerifyOp(const std::shared_ptr<EcGroup>& group,
                                       const std::vector<EcPoint>& stm,
                                       const std::vector<EcPoint>& proof_stm,
                                       const Challenge& challenge);

 private:
  MPInt GenChallenge(const SigmaGenerator& generators,
                     const std::vector<EcPoint>& statement,
                     const std::vector<EcPoint>& rnd_statement,
                     yacl::ByteContainerView other_info = {}) const;
  void CheckParms() const;

  SigmaConfig config_;
  std::shared_ptr<EcGroup> group_ref_;
  SigmaGenerator generators_;
};

}  // namespace examples::zkp
