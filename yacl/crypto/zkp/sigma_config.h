// Copyright 2022 Ant Group Co., Ltd.
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

#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/crypto/hash/hash_interface.h"

namespace yacl::crypto {

// EC-based Sigma proof systems should be implemented over prime-order ecc
// groups.
const CurveName kSigmaEcName = "secp256k1";
const std::string kSigmaEcLib = "OpenSSL";

// Sigma proof type for different group homomorphisms(GH) f:  (G, +) -> (H, ^).
// Generators of group H: h1, h2, h3, ..., hn. Note that we should determine a
// (secure) generation method of generators of group H before running the proof
// system.
enum class SigmaType {
  // Description: know the result of discrete logarithm.
  // f : x -> h1^x (1 1 1, 1 elements in G, 1 Generator and 1 elements in H).
  // Secret: x (in group G).
  // Statement:  z = h1^x (in group H).
  Dlog,
  // Description: know the opening of Pedersen commitment.
  // f : (x1, x2) -> h1^x1·h2^x2 (2 2 1),
  // Secret: x1, x2,
  // Statement:  z = h1^x1·h2^x2.
  Pedersen,
  // Description: know the representation over generators h1, ..., hn.
  // f : (x1, x2, ..., xn) -> h1^x1·h2^x2·...·hn^xn (n n 1),
  // Secret: x1, x2, ..., xn,
  // Statement:  z = h1^x1·h2^x2·...·hn^xn.
  Representation,
  // Description: know results of several discrete logarithm.
  // f : (x1, x2, ..., xn) -> (h1^x1, h2^x2, ..., hn^xn) (n n n),
  // Secret: x1, x2, ..., xn,
  // Statement:  z = (h1^x1, h2^x2, ..., hn^xn).
  SeveralDlog,
  // Description: know equality of two discrete logarithm.
  // f : x -> h1^x, h2^x (1 2 2),
  // Secret: x,
  // Statement:  z1 = h1^x, z2 = h2^x.
  DlogEq,
  // Description: know equality of several discrete logarithm.
  // f : x -> h1^x, h2^x2, ..., hn^xn (1 n n),
  // Secret: x,
  // Statement:  z1 = h1^x, z2 = h2^x, ..., zn = hn^x.
  SeveralDlogEq,
  // Description: know correctness of Diffie-Hellman Keys. (1 2 2)
  // f : It's underlying homomorphism is DlogEq.
  // Secret: x1,
  // Statement:  z1 = h1^x1, z2 = h1^x2, z3 = h1^{x1·x2} = z2^x1,
  // Generators define & transform: h1 = h1, h2 = z2,
  // Transformed statement: z1 = h1^x1, z3 = h2^x1 (Actually DlogEq).
  DHTripple,
  // Description: know the multiplication relation of three Pedersen commitments
  // (z1, z2, z3) with x3 = x1 · x2. (5 2 3)
  // f : It's underlying homomorphism is Pedersen. We don't count x3 as a
  // secret below, cause it's a derived secret from x1, x2.
  // Secret: x1, r1, x2, r2, x3 (= x1·x2 is a derived witness), r3
  // Statement:
  //             z1 = h1^x1·h2^r1,
  //             z2 = h1^x2·h2^r2,
  //             z3 = h1^x3·h2^r3,
  //             and, x3 = x1 * x2,
  // Generators define & transform: h1 = h1, h2 = h2, h3 = z1
  // Transformed statement:
  //             z1 = h1^x1·h2^r1,
  //             z2 = h1^x2·h2^r2,
  //             z3 = h3^x2·h2^(r3-x2·r1) (implying z3 has x3 = x1 * x2),
  PedersenMult,  // Not impl now!
  // Description: know underlying multiplication relation of three Pedersen
  //   commitments, but here we could choose to open a pair (x, r).
  // f : It's underlying homomorphism is Pedersen.
  // Secret: x1, r1, (x2, r2), x3, r3 [Choose open x2, r2]
  PedersenMultOpenOne,  // Not impl now!
};

struct SigmaConfig {
  SigmaType type;        // sigma proof type
  uint32_t num_witness;  // number of witness (in group G),0 means varied size
  uint32_t num_rnd_witness;  // number of random witness
  uint32_t num_generator;    // number of generator
  uint32_t num_statement;    // number of statement (in group H)
  bool dyn_size_flag =
      false;  // true for any meta has dynamic attrs, default set to false
  HashAlgorithm ro_type =
      HashAlgorithm::BLAKE3;  // hash type for non-interactive proof
  PointOctetFormat point_format =
      PointOctetFormat::Autonomous;  // Ec point serialization mod

  SigmaConfig SetDynNum(uint32_t n);

  bool Equals(SigmaConfig rhs) const;
  bool IsQualified() const;
};

SigmaConfig GetSigmaConfig(SigmaType type);
SigmaConfig GetRepresentation(uint64_t num);
SigmaConfig GetSeveralDlogEq(uint64_t num);
SigmaConfig GetSeveralDlog(uint64_t num);

//
// Alias for sigma proof systems
//
using Witness = std::vector<MPInt>;
using Challenge = MPInt;
using SigmaProof = std::vector<MPInt>;
using SigmaGenerator = std::vector<EcPoint>;
using SigmaStatement = std::vector<EcPoint>;

struct SigmaBatchProof {
  SigmaProof proof;
  SigmaStatement rnd_statement;
};

struct SigmaShortProof {
  SigmaProof proof;
  Challenge challenge;
};

}  // namespace yacl::crypto
