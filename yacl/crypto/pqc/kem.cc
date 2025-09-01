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

#include "yacl/crypto/pqc/kem.h"

#include "yacl/base/exception.h"

namespace yacl::crypto {

Kem::Kem(const std::string& alg_name) {
  if (!IsKemAlgEnabled(alg_name)) {
    YACL_THROW("KEM algorithm '{}' is not enabled", alg_name);
  }
  kem_.reset(OQS_KEM_new(alg_name.c_str()), OQS_KEM_free);
}

uint64_t Kem::GetKemAlgCount() { return OQS_KEM_alg_count(); }

std::string Kem::GetKemAlgName(std::size_t alg_id) {
  if (alg_id >= GetKemAlgCount()) {
    YACL_THROW("KEM algorithm ID {} is out of range [0, {})", alg_id,
               GetKemAlgCount());
  }
  return OQS_KEM_alg_identifier(alg_id);
}

std::vector<std::string> Kem::GetSupportedKem() {
  std::vector<std::string> supported_kems;
  for (std::size_t i = 0; i < GetKemAlgCount(); ++i) {
    supported_kems.emplace_back(GetKemAlgName(i));
  }
  return supported_kems;
}

std::vector<std::string> Kem::GetEnabledKem() {
  static auto enabled_kems = []() {
    std::vector<std::string> kems;
    for (const auto& kem : GetSupportedKem()) {
      if (IsKemAlgEnabled(kem)) {
        kems.emplace_back(kem);
      }
    }
    return kems;
  }();
  return enabled_kems;
}

bool Kem::IsKemAlgEnabled(const std::string& alg_name) {
  return OQS_KEM_alg_is_enabled(alg_name.c_str());
}

std::pair<std::vector<uint8_t>, std::vector<uint8_t>> Kem::GenKeyPair() const {
  std::vector<uint8_t> pk(GetPublicKeySize());
  std::vector<uint8_t> sk(GetSecretKeySize());
  auto ret = kem_->keypair(pk.data(), sk.data());
  if (ret != OQS_STATUS::OQS_SUCCESS) {
    YACL_THROW("Failed to generate key pair");
  }
  return std::make_pair(std::move(pk), std::move(sk));
}

std::pair<std::vector<uint8_t>, std::vector<uint8_t>> Kem::Encapsulate(
    ByteContainerView pk) const {
  YACL_ENFORCE(pk.size() == GetPublicKeySize(), "Invalid public key size");
  std::vector<uint8_t> ciphertext(GetCiphertextSize());
  std::vector<uint8_t> shared_secret(GetSharedSecretSize());
  auto ret = kem_->encaps(ciphertext.data(), shared_secret.data(), pk.data());
  if (ret != OQS_STATUS::OQS_SUCCESS) {
    YACL_THROW("Failed to encapsulate");
  }
  return std::make_pair(std::move(ciphertext), std::move(shared_secret));
}

std::vector<uint8_t> Kem::Decapsulate(ByteContainerView sk,
                                      ByteContainerView ciphertext) const {
  YACL_ENFORCE(sk.size() == GetSecretKeySize(), "Invalid secret key size");
  YACL_ENFORCE(ciphertext.size() == GetCiphertextSize(),
               "Invalid ciphertext size");
  std::vector<uint8_t> shared_secret(GetSharedSecretSize());
  auto ret = kem_->decaps(shared_secret.data(), ciphertext.data(), sk.data());
  if (ret != OQS_STATUS::OQS_SUCCESS) {
    YACL_THROW("Failed to decapsulate");
  }
  return shared_secret;
}

}  // namespace yacl::crypto
