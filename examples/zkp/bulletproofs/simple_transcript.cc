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

#include "simple_transcript.h"

#include "yacl/base/exception.h"
#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/crypto/hash/hash_utils.h"
#include "yacl/math/mpint/mp_int.h"

namespace examples::zkp {

// Constants
constexpr uint8_t SimpleTranscript::PROTOCOL_LABEL[];
constexpr uint8_t SimpleTranscript::APP_LABEL[];

SimpleTranscript::SimpleTranscript(yacl::ByteContainerView initial_label) {
  hasher_.Update(PROTOCOL_LABEL);
  hasher_.Update(APP_LABEL);
  hasher_.Update(initial_label);
}

void SimpleTranscript::Absorb(yacl::ByteContainerView label,
                            yacl::ByteContainerView data) {
  AbsorbU64(data.size());
  hasher_.Update(label);
  hasher_.Update(data);
}

void SimpleTranscript::AbsorbScalar(yacl::ByteContainerView label,
                                  const yacl::math::MPInt& scalar) {
  auto scalar_bytes = scalar.Serialize(); 
  AbsorbU64(scalar_bytes.size()); 
  hasher_.Update(label);
  hasher_.Update(yacl::ByteContainerView(scalar_bytes.data(), scalar_bytes.size()));
}

void SimpleTranscript::ValidateAndAbsorbEcPoint(
    const std::shared_ptr<yacl::crypto::EcGroup>& curve,
    yacl::ByteContainerView label,
    const yacl::crypto::EcPoint& point) {
  // Validate that the point is not infinity
  YACL_ENFORCE(!curve->IsInfinity(point), "Point cannot be infinity");
  
  // After validation, absorb the point
  AbsorbEcPoint(curve, label, point);
}

void SimpleTranscript::AbsorbEcPoint(
    const std::shared_ptr<yacl::crypto::EcGroup>& curve,
    yacl::ByteContainerView label,
    const yacl::crypto::EcPoint& point) {
  auto encoded = curve->SerializePoint(point);
  AbsorbU64(encoded.size());
  hasher_.Update(label);
  hasher_.Update(yacl::ByteContainerView(encoded.data(), encoded.size()));
}

void SimpleTranscript::RangeProofDomainSep(size_t n, size_t m) {
  hasher_.Update(yacl::ByteContainerView("range-proof"));
  AbsorbU64(n);  // number of bits
  AbsorbU64(m);  // number of values/parties
}

void SimpleTranscript::InnerProductDomainSep(size_t n) {
  hasher_.Update(yacl::ByteContainerView("inner-product"));
  AbsorbU64(n);  // vector length
}

yacl::math::MPInt SimpleTranscript::ChallengeMPInt(
    yacl::ByteContainerView label,
    const yacl::math::MPInt& order) {
  auto bytes = Squeeze(label);
  yacl::math::MPInt challenge;
  challenge.FromMagBytes(yacl::ByteContainerView(bytes.data(), bytes.size()));
  challenge = challenge % order;
  return challenge;
}

yacl::Buffer SimpleTranscript::Squeeze(yacl::ByteContainerView label) {
  hasher_.Update(label);
  auto hash = hasher_.CumulativeHash();
  return yacl::Buffer(hash.data(), hash.size());
}

yacl::Buffer SimpleTranscript::SqueezeBytes(
    yacl::ByteContainerView label,
    size_t num_bytes) {
  // First get a hash
  auto initial_bytes = Squeeze(label);
  
  // If we need more bytes than the hash provides
  if (num_bytes > initial_bytes.size()) {
    yacl::Buffer result(num_bytes);
    size_t bytes_copied = 0;
    
    // Copy the initial hash
    std::memcpy(result.data(), initial_bytes.data(), initial_bytes.size());
    bytes_copied = initial_bytes.size();
    
    // Keep hashing until we have enough bytes
    while (bytes_copied < num_bytes) {
      hasher_.Update(yacl::ByteContainerView("more"));
      auto more_bytes = hasher_.CumulativeHash();
      size_t to_copy = std::min(more_bytes.size(), num_bytes - bytes_copied);
      std::memcpy(static_cast<uint8_t*>(result.data()) + bytes_copied, 
                 more_bytes.data(), 
                 to_copy);
      bytes_copied += to_copy;
    }
    
    return result;
  }
  
  // If we need fewer bytes than the hash provides, truncate
  return yacl::Buffer(initial_bytes.data(),
                     std::min<size_t>(num_bytes, initial_bytes.size()));
}

}  // namespace examples::zkp 