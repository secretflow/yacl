// Copyright 2024 Ant Group Co., Ltd
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

#include "yacl/crypto/vss/vss.h"

#include "gtest/gtest.h"
#include "spdlog/spdlog.h"

#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/crypto/vss/poly.h"
#include "yacl/math/mpint/mp_int.h"

namespace yacl::crypto::test {

TEST(VerifiableSecretSharingTest, TestCreateAndVerifyShares) {
  // Create an elliptic curve group using the SM2 algorithm
  std::unique_ptr<EcGroup> ec_group = EcGroupFactory::Instance().Create("sm2");

  // Get the order of the elliptic curve group as the modulus
  MPInt modulus = ec_group->GetOrder();

  // Define the secret to be shared
  MPInt original_secret("1234567890");

  // Create a VerifiableSecretSharing instance with parameters (total_shares,
  // required_shares, modulus)
  yacl::crypto::VerifiableSecretSharing vss(20, 10, modulus);

  // Initialize a polynomial for the secret sharing scheme
  yacl::crypto::Polynomial polynomial(modulus);

  // Generate shares and commitments for the secret
  using ShareAndCommitPair =
      std::pair<std::vector<yacl::crypto::VerifiableSecretSharing::Share>,
                std::vector<yacl::crypto::EcPoint>>;
  ShareAndCommitPair shares_and_commits =
      vss.CreateShareWithCommits(original_secret, ec_group, polynomial);

  // Extract the shares from the shares_and_commits pair
  std::vector<yacl::crypto::VerifiableSecretSharing::Share> shares(10);
  for (size_t i = 0; i < shares.size(); i++) {
    shares[i] = shares_and_commits.first[i + 1];
  }

  // Reconstruct the secret using the shares and the polynomial
  MPInt reconstructed_secret = vss.RecoverSecret(shares);
  // Check if the reconstructed secret matches the original secret
  EXPECT_EQ(reconstructed_secret, original_secret);

  // Verify commitments for each share
  for (size_t i = 0; i < shares.size(); i++) {
    // Verify the commitment for a share using the EC group, share, commitments,
    // and modulus
    bool is_verified =
        yacl::crypto::VerifyCommits(ec_group, shares_and_commits.first[i],
                                    shares_and_commits.second, modulus);

    // Check if the commitment verification result is successful
    EXPECT_EQ(is_verified, 1);
  }
}
}  // namespace yacl::crypto::test
