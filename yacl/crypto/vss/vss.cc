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

namespace yacl::crypto {

// Generate shares for the Verifiable Secret Sharing scheme.
// Generate shares for the given secret using the provided polynomial.
std::vector<VerifiableSecretSharing::Share>
VerifiableSecretSharing::CreateShare(const MPInt& secret,
                                     Polynomial& poly) const {
  // Create a polynomial with the secret as the constant term and random
  // coefficients.
  std::vector<MPInt> coefficients(this->GetThreshold());
  poly.CreatePolynomial(secret, this->GetThreshold());

  std::vector<MPInt> xs(total_);
  std::vector<MPInt> ys(total_);

  // Vector to store the generated shares (x, y) for the Verifiable Secret
  // Sharing scheme.
  std::vector<VerifiableSecretSharing::Share> shares;

  // Generate shares by evaluating the polynomial at random points xs.
  for (size_t i = 0; i < total_; i++) {
    MPInt x_i;
    MPInt::RandomLtN(prime_, &x_i);

    // EvaluatePolynomial uses Horner's method.
    // Evaluate the polynomial at the point x_i to compute the share's
    // y-coordinate (ys[i]).
    poly.EvaluatePolynomial(x_i, &ys[i]);

    xs[i] = x_i;
    shares.push_back({xs[i], ys[i]});
  }

  return shares;
}

// Generate shares with commitments for the Verifiable Secret Sharing scheme.
VerifiableSecretSharing::ShareWithCommitsResult
VerifiableSecretSharing::CreateShareWithCommits(
    const MPInt& secret,
    const std::unique_ptr<yacl::crypto::EcGroup>& ecc_group,
    Polynomial& poly) const {
  // Create a polynomial with the secret as the constant term and random
  // coefficients.
  poly.CreatePolynomial(secret, this->threshold_);

  std::vector<MPInt> xs(this->total_);
  std::vector<MPInt> ys(this->total_);
  std::vector<VerifiableSecretSharing::Share> shares(this->total_);

  // Generate shares by evaluating the polynomial at random points xs.
  for (size_t i = 0; i < this->total_; i++) {
    MPInt x_i;
    MPInt::RandomLtN(this->prime_, &x_i);

    poly.EvaluatePolynomial(x_i, &ys[i]);
    xs[i] = x_i;
    shares[i] = {xs[i], ys[i]};
  }

  // Generate commitments for the polynomial coefficients using the elliptic
  // curve group.
  std::vector<yacl::crypto::EcPoint> commits =
      CreateCommits(ecc_group, poly.GetCoeffs());

  return std::make_pair(shares, commits);
}

// Recover the secret from the shares using Lagrange interpolation.
MPInt VerifiableSecretSharing::RecoverSecret(
    absl::Span<const VerifiableSecretSharing::Share> shares) const {
  YACL_ENFORCE(shares.size() >= threshold_);

  MPInt secret(0);
  std::vector<MPInt> xs(threshold_);
  std::vector<MPInt> ys(threshold_);

  // Extract xs and ys from the given shares.
  for (size_t i = 0; i < threshold_; i++) {
    xs[i] = shares[i].x;
    ys[i] = shares[i].y;
  }

  // Use Lagrange interpolation to recover the secret from the shares.
  Polynomial poly(this->prime_);
  poly.LagrangeInterpolation(xs, ys, &secret);

  return secret;
}

// Generate commitments for the given coefficients using the provided elliptic
// curve group.
std::vector<yacl::crypto::EcPoint> CreateCommits(
    const std::unique_ptr<yacl::crypto::EcGroup>& ecc_group,
    const std::vector<MPInt>& coefficients) {
  std::vector<yacl::crypto::EcPoint> commits(coefficients.size());
  for (size_t i = 0; i < coefficients.size(); i++) {
    // Commit each coefficient by multiplying it with the base point of the
    // group.
    commits[i] = ecc_group->MulBase(coefficients[i]);
  }
  return commits;
}

// Verify the commitments and shares in the Verifiable Secret Sharing scheme.
bool VerifyCommits(const std::unique_ptr<yacl::crypto::EcGroup>& ecc_group,
                   const VerifiableSecretSharing::Share& share,
                   const std::vector<yacl::crypto::EcPoint>& commits,
                   const MPInt& prime) {
  // Compute the expected commitment of the share.y by multiplying it with the
  // base point.
  yacl::crypto::EcPoint expected_gy = ecc_group->MulBase(share.y);

  MPInt x_pow_i(1);
  yacl::crypto::EcPoint gy = commits[0];

  // Evaluate the Lagrange polynomial at x = share.x to compute the share.y and
  // verify it.
  for (size_t i = 1; i < commits.size(); i++) {
    x_pow_i = x_pow_i.MulMod(share.x, prime);
    gy = ecc_group->Add(gy, ecc_group->Mul(commits[i], x_pow_i));
  }

  // Compare the computed gy with the expected_gy to verify the commitment.
  return ecc_group->PointEqual(expected_gy, gy);
}

}  // namespace yacl::crypto
