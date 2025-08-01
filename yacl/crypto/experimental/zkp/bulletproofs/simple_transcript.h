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

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "yacl/base/exception.h"
#include "yacl/crypto/ecc/ec_point.h"
#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/crypto/hash/hash_utils.h"
#include "yacl/math/mpint/mp_int.h"

namespace examples::zkp {

/**
 * @brief SimpleTranscript error codes
 */
enum class TranscriptError {
  VerificationError,
};

/**
 * @brief A simple transcript for zero-knowledge proof protocols
 *
 * This class provides functionality similar to Merlin transcripts used in
 * the Bulletproofs paper, but simplified to use YACL cryptographic primitives.
 */
class SimpleTranscript {
 public:
  /**
   * @brief Construct a new SimpleTranscript with an optional initial message
   *
   * @param label Optional label to initialize the transcript
   */
  explicit SimpleTranscript(std::string_view label = "");

  /**
   * @brief Append a domain separator for an n-bit, m-party range proof
   *
   * @param n The number of bits in the range proof
   * @param m The number of parties
   */
  void RangeProofDomainSep(uint64_t n, uint64_t m);

  /**
   * @brief Append a domain separator for a length-n inner product proof
   *
   * @param n The length of the inner product
   */
  void InnerproductDomainSep(uint64_t n);

  /**
   * @brief Append a scalar with the given label
   *
   * @param label The label for the scalar
   * @param scalar The scalar value to append
   */
  void AppendScalar(std::string_view label, const yacl::math::MPInt& scalar);

  /**
   * @brief Append a point with the given label
   *
   * @param label The label for the point
   * @param point The elliptic curve point to append
   * @param curve The elliptic curve group (needed for serialization)
   */
  void AppendPoint(std::string_view label, const yacl::crypto::EcPoint& point,
                   const std::shared_ptr<yacl::crypto::EcGroup>& curve);

  /**
   * @brief Check that a point is not the identity, then append it to the
   * transcript
   *
   * @param label The label for the point
   * @param point The elliptic curve point to validate and append
   * @param curve The elliptic curve group
   * @return true if the point was valid and appended
   * @throw yacl::Exception if the point is the identity
   */
  void ValidateAndAppendPoint(
      std::string_view label, const yacl::crypto::EcPoint& point,
      const std::shared_ptr<yacl::crypto::EcGroup>& curve);

  /**
   * @brief Compute a labeled challenge scalar
   *
   * @param label The label for the challenge
   * @param curve The elliptic curve group (to get the order)
   * @return A scalar challenge derived from the transcript state
   */
  yacl::math::MPInt ChallengeScalar(
      std::string_view label,
      const std::shared_ptr<yacl::crypto::EcGroup>& curve);

  /**
   * @brief Append a message to the transcript
   *
   * @param label The label for the message
   * @param message The message data
   */
  void AppendMessage(std::string_view label, std::string_view message);

  /**
   * @brief Append a uint64_t value to the transcript
   *
   * @param label The label for the value
   * @param value The value to append
   */
  void AppendU64(std::string_view label, uint64_t value);

  /**
   * @brief Get challenge bytes from the transcript
   *
   * @param label The label for the challenge
   * @param dest Buffer to receive the challenge bytes
   * @param length Length of the buffer
   */
  void ChallengeBytes(std::string_view label, uint8_t* dest, size_t length);

  /**
   * @brief Get a const reference to the internal state of the transcript.
   * FOR DEBUGGING PURPOSES ONLY.
   *
   * @return const std::vector<uint8_t>& The internal state hash.
   */
  const std::vector<uint8_t>& GetState() const { return state_; }

  /**
   * @brief Append a domain separator for a constraint system.
   */
  void R1csDomainSep();

  /**
   * @brief Commit a domain separator for a CS without randomized constraints.
   */
  void R1cs1phaseDomainSep();

  /**
   * @brief Commit a domain separator for a CS with randomized constraints.
   */
  void R1cs2phaseDomainSep();

 private:
  // The internal state of the transcript
  std::vector<uint8_t> state_;

  // Update the internal state with new data
  void UpdateState(const std::vector<uint8_t>& data);
};

}  // namespace examples::zkp