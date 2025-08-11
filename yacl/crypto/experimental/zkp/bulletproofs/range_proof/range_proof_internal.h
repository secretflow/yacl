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

#include <memory>

#include "yacl/crypto/experimental/zkp/bulletproofs/errors.h"
#include "yacl/crypto/experimental/zkp/bulletproofs/generators.h"
#include "yacl/crypto/experimental/zkp/bulletproofs/range_proof/range_proof.h"
#include "yacl/crypto/experimental/zkp/bulletproofs/simple_transcript.h"
#include "yacl/crypto/experimental/zkp/bulletproofs/util.h"

// This header contains the internal implementation details (Dealer, Party)
// for the MPC range proof protocol. It should only be included by
// range_proof.cc

namespace examples::zkp {

namespace internal {

// MPC Message Structs
struct BitCommitment {
  yacl::crypto::EcPoint V_j;
  yacl::crypto::EcPoint A_j;
  yacl::crypto::EcPoint S_j;
};

struct BitChallenge {
  yacl::math::MPInt y;
  yacl::math::MPInt z;
};

struct PolyCommitment {
  yacl::crypto::EcPoint T_1_j;
  yacl::crypto::EcPoint T_2_j;
};

struct PolyChallenge {
  yacl::math::MPInt x;
};

class ProofShare {
 public:
  yacl::math::MPInt t_x;
  yacl::math::MPInt t_x_blinding;
  yacl::math::MPInt e_blinding;
  std::vector<yacl::math::MPInt> l_vec;
  std::vector<yacl::math::MPInt> r_vec;
};

// Party state machine classes
// These were previously in mpc/party.h
class PartyAwaitingPolyChallenge;

class PartyAwaitingBitChallenge {
 public:
  PartyAwaitingBitChallenge(size_t n, uint64_t v, yacl::math::MPInt v_blinding,
                            size_t j,
                            std::shared_ptr<const PedersenGens> pc_gens,
                            yacl::math::MPInt a_blinding,
                            yacl::math::MPInt s_blinding,
                            std::vector<yacl::math::MPInt> s_L,
                            std::vector<yacl::math::MPInt> s_R);

  std::pair<PartyAwaitingPolyChallenge, PolyCommitment> ApplyChallenge(
      const std::shared_ptr<yacl::crypto::EcGroup>& curve,
      const BitChallenge& vc);

 private:
  size_t n_;
  uint64_t v_;
  yacl::math::MPInt v_blinding_;
  size_t j_;
  std::shared_ptr<const PedersenGens> pc_gens_;
  yacl::math::MPInt a_blinding_;
  yacl::math::MPInt s_blinding_;
  std::vector<yacl::math::MPInt> s_L_;
  std::vector<yacl::math::MPInt> s_R_;
};

class PartyAwaitingPosition {
 public:
  PartyAwaitingPosition(std::shared_ptr<const BulletproofGens> bp_gens,
                        std::shared_ptr<const PedersenGens> pc_gens, size_t n,
                        uint64_t v, yacl::math::MPInt v_blinding,
                        yacl::crypto::EcPoint V);

  Result<std::pair<PartyAwaitingBitChallenge, BitCommitment>> AssignPosition(
      const std::shared_ptr<yacl::crypto::EcGroup>& curve, size_t j);

 private:
  std::shared_ptr<const BulletproofGens> bp_gens_;
  std::shared_ptr<const PedersenGens> pc_gens_;
  size_t n_;
  uint64_t v_;
  yacl::math::MPInt v_blinding_;
  yacl::crypto::EcPoint V_;
};

class PartyAwaitingPolyChallenge {
 public:
  PartyAwaitingPolyChallenge(yacl::math::MPInt v_blinding,
                             yacl::math::MPInt a_blinding,
                             yacl::math::MPInt s_blinding,
                             yacl::math::MPInt offset_zz, VecPoly1 l_poly,
                             VecPoly1 r_poly, Poly2 t_poly,
                             yacl::math::MPInt t_1_blinding,
                             yacl::math::MPInt t_2_blinding);

  Result<ProofShare> ApplyChallenge(
      const std::shared_ptr<yacl::crypto::EcGroup>& curve,
      const PolyChallenge& pc);

 private:
  yacl::math::MPInt v_blinding_;
  yacl::math::MPInt a_blinding_;
  yacl::math::MPInt s_blinding_;
  yacl::math::MPInt offset_zz_;
  VecPoly1 l_poly_;
  VecPoly1 r_poly_;
  Poly2 t_poly_;
  yacl::math::MPInt t_1_blinding_;
  yacl::math::MPInt t_2_blinding_;
};

class Party {
 public:
  static Result<PartyAwaitingPosition> New(
      std::shared_ptr<const BulletproofGens> bp_gens,
      std::shared_ptr<const PedersenGens> pc_gens, uint64_t v,
      const yacl::math::MPInt& v_blinding, size_t n);
};

class DealerAwaitingProofShares;

class DealerAwaitingPolyCommitments {
 public:
  DealerAwaitingPolyCommitments(size_t n, size_t m,
                                std::shared_ptr<SimpleTranscript> transcript,
                                std::shared_ptr<const BulletproofGens> bp_gens,
                                std::shared_ptr<const PedersenGens> pc_gens,
                                BitChallenge bit_challenge,
                                std::vector<BitCommitment> bit_commitments,
                                yacl::crypto::EcPoint A,
                                yacl::crypto::EcPoint S);

  Result<std::pair<DealerAwaitingProofShares, PolyChallenge>>
  ReceivePolyCommitments(const std::shared_ptr<yacl::crypto::EcGroup>& curve,
                         const std::vector<PolyCommitment>& poly_commitments);

 private:
  size_t n_;
  size_t m_;
  std::shared_ptr<SimpleTranscript> transcript_;
  std::shared_ptr<const BulletproofGens> bp_gens_;
  std::shared_ptr<const PedersenGens> pc_gens_;
  BitChallenge bit_challenge_;
  std::vector<BitCommitment> bit_commitments_;
  yacl::crypto::EcPoint A_;
  yacl::crypto::EcPoint S_;
};

class DealerAwaitingBitCommitments {
 public:
  DealerAwaitingBitCommitments(size_t n, size_t m,
                               std::shared_ptr<SimpleTranscript> transcript,
                               std::shared_ptr<const BulletproofGens> bp_gens,
                               std::shared_ptr<const PedersenGens> pc_gens);

  Result<std::pair<DealerAwaitingPolyCommitments, BitChallenge>>
  ReceiveBitCommitments(const std::shared_ptr<yacl::crypto::EcGroup>& curve,
                        const std::vector<BitCommitment>& bit_commitments);

 private:
  size_t n_;
  size_t m_;
  std::shared_ptr<SimpleTranscript> transcript_;
  std::shared_ptr<const BulletproofGens> bp_gens_;
  std::shared_ptr<const PedersenGens> pc_gens_;
};

class DealerAwaitingProofShares {
 public:
  DealerAwaitingProofShares(
      size_t n, size_t m, std::shared_ptr<SimpleTranscript> transcript,
      std::shared_ptr<const BulletproofGens> bp_gens,
      std::shared_ptr<const PedersenGens> pc_gens, BitChallenge bit_challenge,
      std::vector<BitCommitment> bit_commitments, PolyChallenge poly_challenge,
      std::vector<PolyCommitment> poly_commitments, yacl::crypto::EcPoint A,
      yacl::crypto::EcPoint S, yacl::crypto::EcPoint T_1,
      yacl::crypto::EcPoint T_2);

  // Assembles the final aggregated RangeProof from the given proof_shares
  Result<RangeProof> AssembleShares(
      const std::shared_ptr<yacl::crypto::EcGroup>& curve,
      const std::vector<ProofShare>& proof_shares);

 private:
  size_t n_;
  size_t m_;
  std::shared_ptr<SimpleTranscript> transcript_;
  std::shared_ptr<const BulletproofGens> bp_gens_;
  std::shared_ptr<const PedersenGens> pc_gens_;
  BitChallenge bit_challenge_;
  std::vector<BitCommitment> bit_commitments_;
  PolyChallenge poly_challenge_;
  std::vector<PolyCommitment> poly_commitments_;
  yacl::crypto::EcPoint A_;
  yacl::crypto::EcPoint S_;
  yacl::crypto::EcPoint T_1_;
  yacl::crypto::EcPoint T_2_;
};

class Dealer {
 public:
  static Result<DealerAwaitingBitCommitments> New(
      std::shared_ptr<const BulletproofGens> bp_gens,
      std::shared_ptr<const PedersenGens> pc_gens,
      std::shared_ptr<SimpleTranscript> transcript, size_t n, size_t m);
};

}  // namespace internal
}  // namespace examples::zkp