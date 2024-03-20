/*
 * Copyright 2024 Ant Group Co., Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <iostream>
#include <utility>
#include <vector>

#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/crypto/vss/poly.h"
#include "yacl/math/mpint/mp_int.h"

namespace yacl::crypto {

/**
 * Verifiable Secret Sharing (VSS) is a cryptographic technique that
 * allows a secret to be divided into multiple shares, distributed among a group
 * of participants, in such a way that the original secret can only be
 * reconstructed when a sufficient number of participants combine their shares.
 * The key feature of VSS is that it provides a mechanism to verify the
 * correctness of the shares and the reconstruction process without revealing
 * the secret itself.The concept of Secret Sharing is commonly used for secure
 * key management, data protection, and various secure multi-party computations.
 * Verifiable Secret Sharing adds an additional layer of security and trust by
 * allowing participants to independently verify that the shares they receive
 * are valid and that the reconstruction process is executed correctly.
 *
 * Here's a simplified explanation of how Verifiable Secret Sharing works:
 * 1. Secret Sharing: The original secret is divided into multiple shares using
 * a specific algorithm. The threshold value is set, which represents the
 * minimum number of shares required to reconstruct the secret.
 *
 * 2. Distribution: Each participant receives one share of the secret. The
 * shares are distributed in such a way that no individual share contains enough
 * information to reconstruct the original secret.
 *
 * 3. Verification: Verifiable Secret Sharing introduces an additional step of
 * verification. Each participant can verify the authenticity of their own share
 * and the shares of others. This is typically achieved through cryptographic
 * techniques and mathematical proofs.
 *
 * 4. Reconstruction: To reconstruct the original secret, a minimum threshold of
 * participants must collaborate by combining their shares. The algorithm
 * ensures that with less than the threshold number of shares, the secret
 * remains secure and unrecoverable.
 *
 * Verifiable Secret Sharing has applications in various fields, including
 * secure multiparty computation, key management, digital signatures, and secure
 * cloud computing. It helps ensure that no single party can compromise the
 * secret, and the verification mechanism enhances the transparency and security
 * of the sharing and reconstruction process.
 *
 * Different cryptographic schemes and protocols exist for achieving Verifiable
 * Secret Sharing, each with its own properties and security guarantees. These
 * schemes may use techniques like polynomial interpolation, cryptographic
 * commitments, and zero-knowledge proofs to achieve the desired properties.
 */
class VerifiableSecretSharing {
 public:
  /**
   * @brief Construct a new Verifiable Secret Sharing object
   *
   * @param total
   * @param threshold
   * @param prime
   */
  VerifiableSecretSharing(size_t total, size_t threshold, const MPInt& prime)
      : total_(total), threshold_(threshold), prime_(prime) {
    YACL_ENFORCE(total >= threshold);
  }

  /**
   * @brief Destroy the Verifiable Secret Sharing object
   *
   */
  ~VerifiableSecretSharing() {}

  /**
   * @brief Structure to hold a share (x, y) in the Verifiable Secret Sharing
   * scheme.
   *
   */
  struct Share {
    MPInt x;  // The x-coordinate of the share.
    MPInt y;  // The y-coordinate of the share.
  };

  /**
   * @brief Generate shares for the given secret using the provided polynomial.
   *
   * @param secret
   * @param poly
   * @return std::vector<Share>
   */
  std::vector<Share> CreateShare(const MPInt& secret, Polynomial& poly) const;

  /**
   * @brief Recover the secret from the given shares using Lagrange
   * interpolation.
   *
   * @param shares
   * @param poly
   * @return MPInt
   */
  MPInt RecoverSecret(absl::Span<const Share> shares) const;

  // New name for the type representing the result of GenerateShareWithCommits
  // function.
  using ShareWithCommitsResult =
      std::pair<std::vector<Share>, std::vector<yacl::crypto::EcPoint>>;

  /**
   * @brief Generate shares with commitments for the given secret and elliptic
   * curve group.
   *
   * @param secret
   * @param ecc_group
   * @param poly
   * @return ShareWithCommitsResult
   */
  ShareWithCommitsResult CreateShareWithCommits(
      const MPInt& secret,
      const std::unique_ptr<yacl::crypto::EcGroup>& ecc_group,
      Polynomial& poly) const;

  /**
   * @brief Get the Total object
   *
   * @return size_t
   */
  size_t GetTotal() const { return total_; }

  /**
   * @brief Get the threshold (minimum number of shares required to reconstruct
   * the secret.
   *
   * @return size_t
   */
  size_t GetThreshold() const { return threshold_; }

  /**
   * @brief Get the prime modulus used in the scheme.
   *
   * @return MPInt
   */
  MPInt GetPrime() const { return prime_; }

 private:
  size_t total_;      // Total number of shares in the scheme.
  size_t threshold_;  // Minimum number of shares required to reconstruct the
                      // secret.
  MPInt prime_;       // Prime modulus used in the scheme.
};

/**
 * @brief Generate commitments for the given coefficients using the provided
 * elliptic curve group.
 *
 * @param ecc_group
 * @param coefficients
 * @return std::vector<yacl::crypto::EcPoint>
 */
std::vector<yacl::crypto::EcPoint> CreateCommits(
    const std::unique_ptr<yacl::crypto::EcGroup>& ecc_group,
    const std::vector<MPInt>& coefficients);

/**
 * @brief Verify the commitments and shares in the Verifiable Secret Sharing
 * scheme.
 *
 * @param ecc_group
 * @param share
 * @param commits
 * @param prime
 * @return true
 * @return false
 */
bool VerifyCommits(const std::unique_ptr<yacl::crypto::EcGroup>& ecc_group,
                   const VerifiableSecretSharing::Share& share,
                   const std::vector<yacl::crypto::EcPoint>& commits,
                   const MPInt& prime);

}  // namespace yacl::crypto
