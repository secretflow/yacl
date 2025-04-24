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

#include <memory>
#include <string>
#include <vector>

#include "yacl/base/buffer.h"
#include "yacl/base/byte_container_view.h"
#include "yacl/crypto/hash/hash_utils.h"
#include "yacl/crypto/ecc/ec_point.h"
#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/math/mpint/mp_int.h"
#include "yacl/crypto/hash/ssl_hash.h"

namespace examples::zkp {

class SimpleTranscript {
 public:
  // Constants used for domain separation
  static constexpr uint8_t PROTOCOL_LABEL[] = "dom-sep";
  static constexpr uint8_t APP_LABEL[] = "bulletproof-ipa";

  // Constructor: Initialize with a domain separation label
  explicit SimpleTranscript(yacl::ByteContainerView initial_label);

  // Absorb data into the transcript state with a label
  void Absorb(yacl::ByteContainerView label, yacl::ByteContainerView data);

  // Absorb a scalar value into the transcript
  void AbsorbScalar(yacl::ByteContainerView label, const yacl::math::MPInt& scalar);

  // Absorb an EC point after validating it
  void ValidateAndAbsorbEcPoint(const std::shared_ptr<yacl::crypto::EcGroup>& curve,
                               yacl::ByteContainerView label,
                               const yacl::crypto::EcPoint& point);

  // Absorb an EC point without validation
  void AbsorbEcPoint(const std::shared_ptr<yacl::crypto::EcGroup>& curve,
                     yacl::ByteContainerView label,
                     const yacl::crypto::EcPoint& point);

  // Domain separation for range proofs
  void RangeProofDomainSep(size_t n, size_t m);

  // Domain separation for inner product arguments
  void InnerProductDomainSep(size_t n);

  // Get a challenge scalar from the transcript
  yacl::math::MPInt ChallengeMPInt(yacl::ByteContainerView label,
                                  const yacl::math::MPInt& order);

  // Squeeze bytes from the transcript state with a label
  yacl::Buffer Squeeze(yacl::ByteContainerView label);

  // Squeeze specified number of bytes from the transcript
  yacl::Buffer SqueezeBytes(yacl::ByteContainerView label, size_t num_bytes);

 private:
  // Helper to absorb a 64-bit unsigned integer as little-endian bytes
  void AbsorbU64(uint64_t value) {
    uint8_t bytes[8];
    for (int i = 0; i < 8; ++i) {
      bytes[i] = (value >> (i * 8)) & 0xFF;
    }
    hasher_.Update(yacl::ByteContainerView(bytes, sizeof(bytes)));
  }

  std::vector<uint8_t> state_;
  yacl::crypto::SslHash hasher_{yacl::crypto::HashAlgorithm::SHA256};
};

}  // namespace examples::zkp