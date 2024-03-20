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

#include "yacl/crypto/hash/hash_utils.h"
#include "yacl/crypto/zkp/sigma_owh.h"

namespace yacl::crypto {

// This is an implementation of Pedersen commitment scheme depended on the
// `SigmaOWH`.
//
// Papers:
//  - Pedersen92, Non-Interactive and Information-Theoretic Secure Verifiable
//    Secret Sharing, http://link.springer.com/10.1007/3-540-46766-1_9
//
// Pedersen commitment (perfectly hiding, computationally binding)[Pedersen92]:
// ------------------------------------------------------------
//          (x)
//         prover                    verifier
// random z, c=g^x·h^z   c(commit)
//               ----------------------->
//                       x,r(open)
//               ----------------------->
//                                        check if g^x·h^z ?= c
// ------------------------------------------------------------
//
// [Warning] g and h should be generators of EC group such that nobody knows
// math.log(h, g) (log of h base g)[See
// https://crypto.stackexchange.com/questions/94956/what-does-it-mean-for-g-and-h-to-be-indendent-in-pedersen-commitments].
// So we adapt `HashToCurve` method to generate random generators, which
// meets above requirement.
//
class PedersenCommit {
 public:
  explicit PedersenCommit(
      const std::shared_ptr<EcGroup> &group, uint128_t seed = SecureRandU128(),
      HashToCurveStrategy strategy = HashToCurveStrategy::Autonomous)
      : group_ref_(group),
        generators_(SigmaOWH::MakeGenerators(
            GetSigmaConfig(SigmaType::Pedersen), group_ref_, seed, strategy)) {}

  // Generate a Pedersen commitment
  EcPoint Commit(const MPInt &input, const MPInt &blind) const {
    return SigmaOWH::ToStatement(GetSigmaConfig(SigmaType::Pedersen),
                                 group_ref_, generators_,
                                 Witness{input, blind})[0];
  }

  // Open(Verify) a Pedersen commitment
  bool Open(const EcPoint &commit, const MPInt &input,
            const MPInt &blind) const {
    auto commit_check = Commit(input, blind);
    return group_ref_->PointEqual(commit, commit_check);
  }

  //
  // utility functions
  //
  static MPInt HashInput(ByteContainerView input) {
    auto hashed_input = Sha256(input);
    MPInt input_bn;
    input_bn.Deserialize(hashed_input);
    return input_bn;
  }

  static PedersenCommit &GetDefault() {
    static std::shared_ptr<EcGroup> group =
        EcGroupFactory::Instance().Create(kSigmaEcName, ArgLib = kSigmaEcLib);
    static PedersenCommit ctx(group);
    return ctx;
  }

 private:
  const std::shared_ptr<EcGroup> group_ref_;
  SigmaGenerator generators_;
};

inline EcPoint PedersenHashAndCommit(const ByteContainerView &input,
                                     const MPInt &blind) {
  return PedersenCommit::GetDefault().Commit(PedersenCommit::HashInput(input),
                                             blind);
}

inline bool PedersenHashAndOpen(const EcPoint &commit,
                                const ByteContainerView &input,
                                const MPInt &blind) {
  auto input_bn = PedersenCommit::HashInput(input);
  return PedersenCommit::GetDefault().Open(commit, input_bn, blind);
}

}  // namespace yacl::crypto
