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

void SimpleTranscript::AbsorbEcPoint(
    const std::shared_ptr<yacl::crypto::EcGroup>& curve,
    yacl::ByteContainerView label, const yacl::crypto::EcPoint& point) {
  auto encoded = curve->SerializePoint(point);
  AbsorbU64(encoded.size());
  hasher_.Update(label);
  hasher_.Update(yacl::ByteContainerView(encoded.data(), encoded.size()));
}

yacl::math::MPInt SimpleTranscript::ChallengeMPInt(
    yacl::ByteContainerView label, const yacl::math::MPInt& order) {
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

}  // namespace examples::zkp 