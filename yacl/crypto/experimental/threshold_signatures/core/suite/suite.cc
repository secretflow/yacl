// Copyright 2026 Ant Group Co., Ltd.
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

#include "yacl/crypto/experimental/threshold_signatures/core/suite/suite.h"

#include "yacl/crypto/experimental/threshold_signatures/common/errors.h"
#include "yacl/crypto/hash/ssl_hash.h"

namespace tecdsa::core {

namespace {

yacl::crypto::HashAlgorithm ToYaclHashAlgorithm(HashId hash_id) {
  switch (hash_id) {
    case HashId::kSha256:
      return yacl::crypto::HashAlgorithm::SHA256;
    case HashId::kSha512:
      return yacl::crypto::HashAlgorithm::SHA512;
    case HashId::kSm3:
      return yacl::crypto::HashAlgorithm::SM3;
  }

  TECDSA_THROW_ARGUMENT("Unsupported hash id");
}

}  // namespace

const ThresholdSuite& DefaultEcdsaSuite() {
  static const ThresholdSuite kDefault = []() {
    ThresholdSuite suite;
    suite.scheme = SchemeId::kEcdsa;
    suite.curve = CurveId::kSecp256k1;
    suite.transcript_hash = HashId::kSha256;
    suite.commitment_hash = HashId::kSha256;
    suite.message_hash = HashId::kSha256;
    suite.proof_domain_prefix = "GG2019";
    suite.normalize_low_s = true;
    return suite;
  }();
  return kDefault;
}

const ThresholdSuite& DefaultSm2Suite() {
  static const ThresholdSuite kDefault = []() {
    ThresholdSuite suite;
    suite.scheme = SchemeId::kSm2;
    suite.curve = CurveId::kSm2P256V1;
    suite.transcript_hash = HashId::kSm3;
    suite.commitment_hash = HashId::kSm3;
    suite.message_hash = HashId::kSm3;
    suite.proof_domain_prefix = "GG2019";
    suite.normalize_low_s = false;
    return suite;
  }();
  return kDefault;
}

Bytes Hash(HashId hash_id, std::span<const uint8_t> data) {
  yacl::crypto::SslHash hash(ToYaclHashAlgorithm(hash_id));
  return hash.Update(yacl::ByteContainerView(data.data(), data.size()))
      .CumulativeHash();
}

}  // namespace tecdsa::core
