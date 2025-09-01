// Copyright 2025 Ant Group Co., Ltd.
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

// Post-quantum key encapsulation mechanism (KEM) algorithms implementation
//
// This file provides a C++ wrapper for the liboqs library.
// It supports various post-quantum KEM schemes including:
// - ML-KEM
// - Kyber
// - NTRU
// - McEliece
// And more. You can find more information about the liboqs library at
// https://github.com/open-quantum-safe/liboqs

#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "yacl/base/byte_container_view.h"
#include "yacl/base/exception.h"

namespace yacl::crypto {

extern "C" {
#include <oqs/common.h>
#include <oqs/oqs.h>
}

class Kem {
 public:
  explicit Kem(const std::string& alg_name);

  static uint64_t GetKemAlgCount();
  static std::string GetKemAlgName(std::size_t alg_id);
  static std::vector<std::string> GetSupportedKem();
  static std::vector<std::string> GetEnabledKem();
  static bool IsKemAlgEnabled(const std::string& alg_name);

  std::string GetKemAlgVersion() const { return kem_->alg_version; }
  uint64_t GetClaimedNistLevel() const { return kem_->claimed_nist_level; }
  bool IsIndCca() const { return kem_->ind_cca; }
  uint64_t GetPublicKeySize() const { return kem_->length_public_key; }
  uint64_t GetSecretKeySize() const { return kem_->length_secret_key; }
  uint64_t GetCiphertextSize() const { return kem_->length_ciphertext; }
  uint64_t GetSharedSecretSize() const { return kem_->length_shared_secret; }

  std::pair<std::vector<uint8_t>, std::vector<uint8_t>> GenKeyPair() const;

  std::pair<std::vector<uint8_t>, std::vector<uint8_t>> Encapsulate(
      ByteContainerView pk) const;

  std::vector<uint8_t> Decapsulate(ByteContainerView sk,
                                   ByteContainerView ciphertext) const;

 private:
  std::shared_ptr<OQS_KEM> kem_{nullptr, [](OQS_KEM* p) { OQS_KEM_free(p); }};
};

}  // namespace yacl::crypto
