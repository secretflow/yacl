// Copyright 2023 Ant Group Co., Ltd.
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

#include <string>
#include <unordered_map>
#include <utility>

#include "yacl/crypto/openssl_wrappers.h"

namespace yacl::crypto {

// -------------------
// Key Pair Generation
// -------------------

// Generate RSA secret key and public key pair, the resulting key pair is stored
// in a single UniquePkey object
[[nodiscard]] openssl::UniquePkey GenRsaKeyPair(unsigned rsa_keylen = 2048);

// Generate SM2 secret key and public key pair, the resulting key pair is stored
// in a single UniquePkey object
[[nodiscard]] openssl::UniquePkey GenSm2KeyPair();

// Generate RSA key pair, and convert the secret key (sk) and public key (pk)
// into "PEM" format buffers, separately
[[nodiscard]] std::pair<Buffer, Buffer> GenRsaKeyPairToPemBuf(
    unsigned rsa_keygen = 2048);

// Generate RSA key pair, and convert the secret key (sk) and public key (pk)
// into "PEM" format buffers, separately
[[nodiscard]] std::pair<Buffer, Buffer> GenSm2KeyPairToPemBuf();

// -------------------
// Load Any Format Key
// -------------------

// Load any (format/type/structure) key from buffer, and return a UniquePkey
// object
[[nodiscard]] openssl::UniquePkey LoadKeyFromBuf(ByteContainerView buf);

// load any (format/type/structure) key from file, and return a UniquePkey
// object
[[nodiscard]] openssl::UniquePkey LoadKeyFromFile(const std::string& file_path);

// ------------------
// Load/Export PEM Key
// ------------------

// Function alias: load pem key from buffer
[[nodiscard]] inline openssl::UniquePkey LoadPemKey(ByteContainerView buf) {
  return LoadKeyFromBuf(buf);
}

// Function alias: load pem key from file
[[nodiscard]] inline openssl::UniquePkey LoadPemKeyFromFile(
    const std::string& file_path) {
  return LoadKeyFromFile(file_path);
}

// Export public key and key parameter to buffer bytes, in pem format
[[nodiscard]] Buffer ExportPublicKeyToPemBuf(
    /* public key */ const openssl::UniquePkey& pkey);

// Export public key and key parameter to file, in pem format
void ExportPublicKeyToPemFile(/* public key */ const openssl::UniquePkey& pkey,
                              const std::string& file_path);

// Export secret key, public key and key parameter to buffer bytes, in pem
// format
[[nodiscard]] Buffer ExportSecretKeyToPemBuf(
    /* secret key, or key pair */ const openssl::UniquePkey& pkey);

// Export secret key, public key and key parameter to file, in pem format
void ExportSecretKeyToPemBuf(
    /* secret key, or key pair */ const openssl::UniquePkey& pkey,
    const std::string& file_path);

// ------------------
// Load/Export DER Key
// ------------------

// Function alias: load der key from buffer
[[nodiscard]] inline openssl::UniquePkey LoadDerKey(ByteContainerView buf) {
  return LoadKeyFromBuf(buf);
}

// Function alias: load der key from file
[[nodiscard]] inline openssl::UniquePkey LoadDerKeyFromFile(
    const std::string& file_path) {
  return LoadKeyFromFile(file_path);
}

// Export public key and key parameter to buffer bytes, in der format
[[nodiscard]] Buffer ExportPublicKeyToDerBuf(
    /* public key */ const openssl::UniquePkey& pkey);

// Export public key and key parameter to file, in der format
void ExportPublicKeyToDerFile(/* public key */ const openssl::UniquePkey& pkey,
                              const std::string& file_path);

// Export secret key, public key and key parameter to buffer bytes, in der
// format
[[nodiscard]] Buffer ExportSecretKeyToDerBuf(
    /* secret key or key pair */ const openssl::UniquePkey& pkey);

// Export secret key, public key and key parameter to file, in der format
void ExportSecretKeyToDerFile(
    /* secret key or key pair */ const openssl::UniquePkey& pkey,
    const std::string& file_path);

// -------------------------------
// Gen/Load/Export X509 Certificate
// -------------------------------

// Self-sign a X509 certificate
[[nodiscard]] openssl::UniqueX509 MakeX509Cert(
    /* issuer's pk */ const openssl::UniquePkey& pk,
    /* issuer's sk */ const openssl::UniquePkey& sk,
    /* subjects info */
    const std::unordered_map<std::string, std::string>& subjects,
    /* time */ unsigned days, HashAlgorithm hash);

// Load x509 certificate from buffer
[[nodiscard]] openssl::UniqueX509 LoadX509Cert(ByteContainerView buf);

// Load x509 certificate from file
[[nodiscard]] openssl::UniqueX509 LoadX509CertFromFile(
    const std::string& file_path);

// Load x509 public key from buffer
[[nodiscard]] openssl::UniquePkey LoadX509CertPublicKeyFromBuf(
    ByteContainerView buf);

// Load x509 public key from file
[[nodiscard]] openssl::UniquePkey LoadX509CertPublicKeyFromFile(
    const std::string& file_path);

// export x509 certificate to buffer
[[nodiscard]] Buffer ExportX509CertToBuf(const openssl::UniqueX509& x509);
void ExportX509CertToFile(const openssl::UniqueX509& x509,
                          const std::string& file_path);

}  // namespace yacl::crypto
