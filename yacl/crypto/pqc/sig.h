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

// Post-quantum signature algorithms implementation
//
// This file provides a C++ wrapper for the liboqs library.
// It supports various post-quantum signature schemes including:
// - ML-DSA
// - Dilithium
// - Falcon
// - SPHINCS+
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

namespace yacl::crypto {

extern "C" {
#include <oqs/common.h>
#include <oqs/oqs.h>
}

class Sig {
 public:
  explicit Sig(const std::string& alg_name);

  static uint64_t GetSigAlgCount();
  static std::string GetSigAlgName(std::size_t alg_id);
  static std::vector<std::string> GetSupportedSig();
  static std::vector<std::string> GetEnabledSig();
  static bool IsSigAlgEnabled(const std::string& alg_name);

  std::string GetSigAlgVersion() const { return sig_->alg_version; }
  uint64_t GetClaimedNistLevel() const { return sig_->claimed_nist_level; }
  bool IsEufCma() const { return sig_->euf_cma; }
  bool IsSigWithCtxSupport() const { return sig_->sig_with_ctx_support; }
  uint64_t GetPublicKeySize() const { return sig_->length_public_key; }
  uint64_t GetSecretKeySize() const { return sig_->length_secret_key; }
  uint64_t GetSignatureSize() const { return sig_->length_signature; }

  std::pair<std::vector<uint8_t>, std::vector<uint8_t>> GenKeyPair() const;

  std::vector<uint8_t> Sign(ByteContainerView sk,
                            ByteContainerView message) const;

  std::vector<uint8_t> SignWithCtxStr(ByteContainerView sk,
                                      ByteContainerView message,
                                      ByteContainerView context) const;

  bool Verify(ByteContainerView pk, ByteContainerView message,
              ByteContainerView signature) const;

  bool VerifyWithCtxStr(ByteContainerView pk, ByteContainerView message,
                        ByteContainerView signature,
                        ByteContainerView context) const;

 private:
  std::shared_ptr<OQS_SIG> sig_{nullptr, [](OQS_SIG* p) { OQS_SIG_free(p); }};
};

}  // namespace yacl::crypto
