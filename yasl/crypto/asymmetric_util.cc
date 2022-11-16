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

#include "yasl/crypto/asymmetric_util.h"

#include <random>

#include "openssl/bio.h"
#include "openssl/bn.h"
#include "openssl/pem.h"
#include "openssl/rsa.h"
#include "openssl/x509v3.h"

#include "yasl/base/exception.h"
#include "yasl/utils/scope_guard.h"

namespace yasl::crypto {

using UniqueBio = std::unique_ptr<BIO, decltype(&BIO_free)>;
using UniqueRsa = std::unique_ptr<RSA, decltype(&RSA_free)>;
using UniqueEVP = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using UniqueX509 = std::unique_ptr<X509, decltype(&X509_free)>;

namespace {

constexpr int kRsaKeyBitSize = 2048;
constexpr int kCertVersion = 2;
constexpr unsigned kSecondsInDay = 24 * 60 * 60;

constexpr std::array<const char*, 6> kSubjectFields = {"C", "ST", "L",
                                                       "O", "OU", "CN"};

inline std::string BioToString(const UniqueBio& bio) {
  int size = BIO_pending(bio.get());
  YASL_ENFORCE_GT(size, 0, "BIO_pending failed.");
  std::string out;
  out.resize(size);
  YASL_ENFORCE_EQ(BIO_read(bio.get(), out.data(), size), size,
                  "Read bio failed.");
  return out;
}

inline void AddX509Extension(X509* cert, int nid, char* value) {
  X509V3_CTX ctx;
  /* This sets the 'context' of the extensions. */
  /* No configuration database */
  X509V3_set_ctx_nodb(&ctx);
  // self signed
  X509V3_set_ctx(&ctx, cert, cert, nullptr, nullptr, 0);
  X509_EXTENSION* ex = X509V3_EXT_nconf_nid(nullptr, &ctx, nid, value);
  YASL_ENFORCE(ex != nullptr);
  X509_add_ext(cert, ex, -1);
  X509_EXTENSION_free(ex);
}

}  // namespace

namespace internal {

UniquePkey CreatePriPkeyFromSm2Pem(ByteContainerView pem) {
  UniqueBio pem_bio(BIO_new_mem_buf(pem.data(), pem.size()), BIO_free);
  EC_KEY* ec_key =
      PEM_read_bio_ECPrivateKey(pem_bio.get(), nullptr, nullptr, nullptr);
  YASL_ENFORCE(ec_key != nullptr, "No ec private key from pem.");
  ON_SCOPE_EXIT([&] { EC_KEY_free(ec_key); });
  EVP_PKEY* pri_key = EVP_PKEY_new();
  YASL_ENFORCE(pri_key != nullptr);
  YASL_ENFORCE_GT(EVP_PKEY_set1_EC_KEY(pri_key, ec_key), 0);
  YASL_ENFORCE_GT(EVP_PKEY_set_alias_type(pri_key, EVP_PKEY_SM2), 0);

  return UniquePkey(pri_key, ::EVP_PKEY_free);
}

UniquePkey CreatePubPkeyFromSm2Pem(ByteContainerView pem) {
  UniqueBio pem_bio(BIO_new_mem_buf(pem.data(), pem.size()), BIO_free);
  EC_KEY* ec_key =
      PEM_read_bio_EC_PUBKEY(pem_bio.get(), nullptr, nullptr, nullptr);
  YASL_ENFORCE(ec_key != nullptr, "No ec public key from pem.");
  ON_SCOPE_EXIT([&] { EC_KEY_free(ec_key); });
  EVP_PKEY* pub_key = EVP_PKEY_new();
  YASL_ENFORCE(pub_key != nullptr);
  YASL_ENFORCE_GT(EVP_PKEY_set1_EC_KEY(pub_key, ec_key), 0);
  YASL_ENFORCE_GT(EVP_PKEY_set_alias_type(pub_key, EVP_PKEY_SM2), 0);

  return UniquePkey(pub_key, ::EVP_PKEY_free);
}

}  // namespace internal

std::tuple<std::string, std::string> CreateSm2KeyPair() {
  // Create sm2 curve
  EC_KEY* ec_key = EC_KEY_new();
  YASL_ENFORCE(ec_key != nullptr);
  ON_SCOPE_EXIT([&] { EC_KEY_free(ec_key); });
  EC_GROUP* ec_group = EC_GROUP_new_by_curve_name(NID_sm2);
  YASL_ENFORCE(ec_group != nullptr);
  ON_SCOPE_EXIT([&] { EC_GROUP_free(ec_group); });
  YASL_ENFORCE_GT(EC_KEY_set_group(ec_key, ec_group), 0);
  YASL_ENFORCE_GT(EC_KEY_generate_key(ec_key), 0);

  // Read private key
  BIO* pri_bio = BIO_new(BIO_s_mem());
  ON_SCOPE_EXIT([&] { BIO_free(pri_bio); });
  YASL_ENFORCE_GT(PEM_write_bio_ECPrivateKey(pri_bio, ec_key, nullptr, nullptr,
                                             0, nullptr, nullptr),
                  0);
  std::string private_key(BIO_pending(pri_bio), '\0');
  YASL_ENFORCE_GT(BIO_read(pri_bio, private_key.data(), private_key.size()), 0);

  // Read public key
  BIO* pub_bio = BIO_new(BIO_s_mem());
  ON_SCOPE_EXIT([&] { BIO_free(pub_bio); });
  YASL_ENFORCE_GT(PEM_write_bio_EC_PUBKEY(pub_bio, ec_key), 0);
  std::string public_key(BIO_pending(pub_bio), '\0');
  YASL_ENFORCE_GT(BIO_read(pub_bio, public_key.data(), public_key.size()), 0);

  return std::make_tuple(public_key, private_key);
}

UniqueRsa CreateRsaFromX509(ByteContainerView x509_public_key) {
  UniqueBio pem_bio(
      BIO_new_mem_buf(x509_public_key.data(), x509_public_key.size()),
      BIO_free);
  X509* cert = PEM_read_bio_X509(pem_bio.get(), nullptr, nullptr, nullptr);
  YASL_ENFORCE(cert, "No X509 from cert.");
  UniqueX509 unique_cert(cert, ::X509_free);
  EVP_PKEY* pubkey = X509_get_pubkey(unique_cert.get());
  YASL_ENFORCE(pubkey, "No pubkey in x509.");
  UniqueEVP unique_pkey(pubkey, ::EVP_PKEY_free);
  RSA* rsa = EVP_PKEY_get1_RSA(unique_pkey.get());
  YASL_ENFORCE(rsa, "No Rsa from pem string.");

  return UniqueRsa(rsa, ::RSA_free);
}

std::string GetPublicKeyFromRsa(const UniqueRsa& rsa, bool x509_pkey) {
  std::string public_key;
  {
    UniqueBio bio(BIO_new(BIO_s_mem()), BIO_free);
    YASL_ENFORCE(bio, "New bio failed.");
    if (x509_pkey) {
      UniqueEVP unique_pkey(EVP_PKEY_new(), ::EVP_PKEY_free);
      YASL_ENFORCE(EVP_PKEY_set1_RSA(unique_pkey.get(), rsa.get()),
                   "Convert rsa to pubkey failed.");
      YASL_ENFORCE(PEM_write_bio_PUBKEY(bio.get(), unique_pkey.get()),
                   "Write public key failed.");
    } else {
      YASL_ENFORCE(PEM_write_bio_RSAPublicKey(bio.get(), rsa.get()),
                   "Write public key failed.");
    }
    int size = BIO_pending(bio.get());
    YASL_ENFORCE_GT(size, 0, "Bad key size.");
    public_key.resize(size);
    YASL_ENFORCE_GT(BIO_read(bio.get(), public_key.data(), size), 0,
                    "Cannot read bio.");
  }
  return public_key;
}

std::tuple<std::string, std::string> CreateRsaKeyPair(bool x509_pkey) {
  std::unique_ptr<BIGNUM, decltype(&BN_free)> exp(BN_new(), BN_free);
  YASL_ENFORCE_EQ(BN_set_word(exp.get(), RSA_F4), 1, "BN_set_word failed.");
  UniqueRsa rsa(RSA_new(), RSA_free);
  YASL_ENFORCE(
      RSA_generate_key_ex(rsa.get(), kRsaKeyBitSize, exp.get(), nullptr),
      "Generate rsa key pair failed.");

  std::string public_key = GetPublicKeyFromRsa(rsa, x509_pkey);

  std::string private_key;
  {
    UniqueBio bio(BIO_new(BIO_s_mem()), BIO_free);
    YASL_ENFORCE(bio, "New bio failed.");
    YASL_ENFORCE(PEM_write_bio_RSAPrivateKey(bio.get(), rsa.get(), nullptr,
                                             nullptr, 0, 0, nullptr),
                 "Write private key failed.");
    int size = BIO_pending(bio.get());
    YASL_ENFORCE_GT(size, 0, "Bad key size.");
    private_key.resize(size);
    YASL_ENFORCE_GT(BIO_read(bio.get(), private_key.data(), size), 0,
                    "Cannot read bio.");
  }

  return std::make_tuple(public_key, private_key);
}

std::tuple<std::string, std::string> CreateRsaCertificateAndPrivateKey(
    const std::unordered_map<std::string, std::string>& subject_map,
    unsigned bit_length, unsigned days) {
  // 1. Create key pair.
  std::unique_ptr<BIGNUM, decltype(&BN_free)> exp(BN_new(), BN_free);
  YASL_ENFORCE_EQ(BN_set_word(exp.get(), RSA_F4), 1, "BN_set_word failed.");
  UniqueRsa rsa(RSA_new(), ::RSA_free);
  YASL_ENFORCE(RSA_generate_key_ex(rsa.get(), bit_length, exp.get(), nullptr),
               "Generate rsa key pair failed.");

  // 2. Assign to EVP_PKEY.
  UniqueEVP evp_pkey(EVP_PKEY_new(), ::EVP_PKEY_free);
  YASL_ENFORCE(EVP_PKEY_assign_RSA(evp_pkey.get(), rsa.get()),
               "Cannot assign rsa.");
  // Ownership transferred to EVP. Let us release ownership from rsa.
  rsa.release();
  // 3. Generate X509 Certificate.
  UniqueX509 x509(X509_new(), ::X509_free);
  // 3.1 v3 & serial number
  // - V3
  X509_set_version(x509.get(), kCertVersion);
  // - random serial number
  std::random_device rd;
  YASL_ENFORCE(ASN1_INTEGER_set(X509_get_serialNumber(x509.get()), rd()) == 1,
               "ASN1_INTEGER_set failed.");
  // 3.2 valid range
  X509_gmtime_adj(X509_get_notBefore(x509.get()), 0);
  X509_gmtime_adj(X509_get_notAfter(x509.get()), days * kSecondsInDay);
  // 3.3 fill rsa public key
  X509_set_pubkey(x509.get(), evp_pkey.get());
  X509_NAME* name = X509_get_subject_name(x509.get());
  // 3.4 set subject fields.
  for (auto& field : kSubjectFields) {
    auto it = subject_map.find(field);
    YASL_ENFORCE(it != subject_map.end(), "Cannot find subject field {}.",
                 field);
    YASL_ENFORCE(X509_NAME_add_entry_by_txt(
                     name, it->first.c_str(), MBSTRING_ASC,
                     reinterpret_cast<const unsigned char*>(it->second.c_str()),
                     -1, -1, 0),
                 "Set x509 name failed.");
  }

  // 3.5 self-signed: issuer name == name.
  YASL_ENFORCE(X509_set_issuer_name(x509.get(), name) == 1,
               "X509_set_issuer_name failed.");
  AddX509Extension(x509.get(), NID_basic_constraints, (char*)"CA:TRUE");
  AddX509Extension(x509.get(), NID_subject_key_identifier, (char*)"hash");
  // 3.6 Do self signing with sha256-rsa.
  YASL_ENFORCE(X509_sign(x509.get(), evp_pkey.get(), EVP_sha256()),
               "Perform self-signing failed.");
  // 4. Write as string.
  UniqueBio pkey_bio(BIO_new(BIO_s_mem()), BIO_free);
  YASL_ENFORCE(PEM_write_bio_PrivateKey(pkey_bio.get(), evp_pkey.get(), nullptr,
                                        nullptr, 0, nullptr, nullptr),
               "Failed PEM_write_bio_PrivateKey.");
  UniqueBio cert_bio(BIO_new(BIO_s_mem()), BIO_free);
  YASL_ENFORCE(PEM_write_bio_X509(cert_bio.get(), x509.get()),
               "Failed PEM_write_bio_X509.");
  return std::make_tuple(BioToString(cert_bio), BioToString(pkey_bio));
}

}  // namespace yasl::crypto