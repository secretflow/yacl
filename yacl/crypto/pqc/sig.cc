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

#include "yacl/crypto/pqc/sig.h"

#include "spdlog/spdlog.h"

#include "yacl/base/byte_container_view.h"
#include "yacl/base/exception.h"

namespace yacl::crypto {

Sig::Sig(const std::string& alg_name) {
  if (!IsSigAlgEnabled(alg_name)) {
    YACL_THROW("SIG algorithm '{}' is not supported or not enabled", alg_name);
  }
  sig_.reset(OQS_SIG_new(alg_name.c_str()), OQS_SIG_free);
}

uint64_t Sig::GetSigAlgCount() { return OQS_SIG_alg_count(); }

std::string Sig::GetSigAlgName(std::size_t alg_id) {
  if (alg_id >= GetSigAlgCount()) {
    YACL_THROW("SIG algorithm ID {} is out of range [0, {})", alg_id,
               GetSigAlgCount());
  }
  return OQS_SIG_alg_identifier(alg_id);
}

std::vector<std::string> Sig::GetAllSigs() {
  static auto supported_sigs = []() {
    std::vector<std::string> sigs;
    for (std::size_t i = 0; i < GetSigAlgCount(); ++i) {
      sigs.emplace_back(GetSigAlgName(i));
    }
    return sigs;
  }();
  return supported_sigs;
}

std::vector<std::string> Sig::GetEnabledSigs() {
  static auto enabled_sigs = []() {
    std::vector<std::string> sigs;
    for (const auto& sig : GetAllSigs()) {
      if (IsSigAlgEnabled(sig)) {
        sigs.emplace_back(sig);
      }
    }
    return sigs;
  }();
  return enabled_sigs;
}

bool Sig::IsSigAlgEnabled(const std::string& alg_name) {
  return OQS_SIG_alg_is_enabled(alg_name.c_str());
}

std::pair<std::vector<uint8_t>, std::vector<uint8_t>> Sig::GenKeyPair() const {
  std::vector<uint8_t> pk(GetPublicKeySize());
  std::vector<uint8_t> sk(GetSecretKeySize());
  auto ret = sig_->keypair(pk.data(), sk.data());
  if (ret != OQS_STATUS::OQS_SUCCESS) {
    YACL_THROW("Failed to generate key pair");
  }
  return std::make_pair(std::move(pk), std::move(sk));
}

std::vector<uint8_t> Sig::Sign(ByteContainerView sk,
                               ByteContainerView message) const {
  std::vector<uint8_t> signature(GetSignatureSize());
  uint64_t signature_len = 0;
  auto ret = sig_->sign(signature.data(), &signature_len, message.data(),
                        message.size(), sk.data());
  if (ret != OQS_STATUS::OQS_SUCCESS) {
    YACL_THROW("Failed to sign message");
  }
  signature.resize(signature_len);
  return signature;
}

std::vector<uint8_t> Sig::SignWithCtxStr(ByteContainerView sk,
                                         ByteContainerView message,
                                         ByteContainerView context) const {
  YACL_ENFORCE(sk.size() == GetSecretKeySize(), "Invalid secret key size");
  YACL_ENFORCE(context.size() > 0, "Context size must be greater than 0");

  std::vector<uint8_t> signature(GetSignatureSize());
  uint64_t signature_len = 0;
  auto ret = sig_->sign_with_ctx_str(signature.data(), &signature_len,
                                     message.data(), message.size(),
                                     context.data(), context.size(), sk.data());
  if (ret != OQS_STATUS::OQS_SUCCESS) {
    YACL_THROW("Failed to sign message with context");
  }
  signature.resize(signature_len);
  return signature;
}

bool Sig::Verify(ByteContainerView pk, ByteContainerView message,
                 ByteContainerView signature) const {
  YACL_ENFORCE(pk.size() == GetPublicKeySize(), "Invalid public key size");
  YACL_ENFORCE(signature.size() <= GetSignatureSize(),
               "Invalid signature size");
  auto ret = sig_->verify(message.data(), message.size(), signature.data(),
                          signature.size(), pk.data());
  return ret == OQS_STATUS::OQS_SUCCESS;
}

bool Sig::VerifyWithCtxStr(ByteContainerView pk, ByteContainerView message,
                           ByteContainerView signature,
                           ByteContainerView context) const {
  YACL_ENFORCE(pk.size() == GetPublicKeySize(), "Invalid public key size");
  YACL_ENFORCE(signature.size() <= GetSignatureSize(),
               "Invalid signature size");
  auto ret = sig_->verify_with_ctx_str(
      message.data(), message.size(), signature.data(), signature.size(),
      context.data(), context.size(), pk.data());
  return ret == OQS_STATUS::OQS_SUCCESS;
}
}  // namespace yacl::crypto
