// Copyright 2019 Ant Group Co., Ltd.
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

#pragma once

#include <tuple>
#include <unordered_map>
#include <vector>

#include "openssl/bio.h"
#include "openssl/evp.h"
#include "openssl/rsa.h"

#include "yasl/base/byte_container_view.h"

namespace yasl::crypto {

using UniqueRsa = std::unique_ptr<RSA, decltype(&RSA_free)>;

namespace internal {

using UniquePkey = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;

UniquePkey CreatePriPkeyFromSm2Pem(ByteContainerView pem);

UniquePkey CreatePubPkeyFromSm2Pem(ByteContainerView pem);

}  // namespace internal

std::tuple<std::string, std::string> CreateSm2KeyPair();

std::tuple<std::string, std::string> CreateRsaKeyPair(bool x509_pkey = false);

UniqueRsa CreateRsaFromX509(ByteContainerView x509_public_key);

std::string GetPublicKeyFromRsa(const UniqueRsa& rsa, bool x509_pkey = false);

std::tuple<std::string, std::string> CreateRsaCertificateAndPrivateKey(
    const std::unordered_map<std::string, std::string>& subject_map,
    unsigned bit_length, unsigned days);

}  // namespace yasl::crypto