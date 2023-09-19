#include "yacl/crypto/primitives/vss/vss.h"

#include "gtest/gtest.h"
#include "spdlog/spdlog.h"

#include "yacl/crypto/base/ecc/ecc_spi.h"
#include "yacl/crypto/primitives/vss/poly.h"
#include "yacl/math/mpint/mp_int.h"

namespace yacl::crypto::test {

TEST(VerifiableSecretSharingTest, TestCreateAndVerifyShares) {
  // Create an elliptic curve group using the SM2 algorithm
  std::unique_ptr<EcGroup> ec_group = EcGroupFactory::Instance().Create("sm2");

  // Get the order of the elliptic curve group as the modulus
  math::MPInt modulus = ec_group->GetOrder();

  // Define the secret to be shared
  math::MPInt original_secret("1234567890");

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
  math::MPInt reconstructed_secret = vss.RecoverSecret(shares);
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
