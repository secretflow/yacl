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

#include "yacl/crypto/key_utils.h"

#include <cstddef>

#include "yacl/crypto/openssl_wrappers.h"
#include "yacl/io/stream/file_io.h"

namespace yacl::crypto {

namespace {

constexpr unsigned kSecondsInDay = 24 * 60 * 60;
constexpr int kX509Version = 3;
constexpr std::array<std::string_view, 6> kX509SubjectFields = {
    /* country */ "C",
    /* state or province name  */ "ST",
    /* locality*/ "L",
    /* organization */ "O",
    /* organizational unit */ "OU",
    /* common name */ "CN"};

inline void AddX509Extension(X509* cert, int nid, char* value) {
  X509V3_CTX ctx;
  /* This sets the 'context' of the extensions. */
  /* No configuration database */
  X509V3_set_ctx_nodb(&ctx);
  // self signed
  X509V3_set_ctx(&ctx, cert, cert, nullptr, nullptr, 0);
  auto ex =
      openssl::UniqueX509Ext(X509V3_EXT_nconf_nid(nullptr, &ctx, nid, value));

  YACL_ENFORCE(ex != nullptr);
  X509_add_ext(cert, ex.get(), -1);
}

// convert bio file to yacl::Buffer
inline Buffer BioToBuf(const openssl::UniqueBio& bio) {
  int num_bytes = BIO_pending(bio.get());
  YACL_ENFORCE_GT(num_bytes, 0, "BIO_pending failed.");

  // read data from bio
  Buffer out(num_bytes);
  YACL_ENFORCE_EQ(BIO_read(bio.get(), out.data(), num_bytes), num_bytes,
                  "Read bio failed.");
  return out;
}

inline Buffer LoadBufFromFile(const std::string& file_path) {
  io::FileInputStream in(file_path);
  Buffer buf(static_cast<int64_t>(in.GetLength()));
  in.Read(buf.data(), buf.size());
  return buf;
}

// this function steals the ownership of key buffer, this is an intended
// behaviour
inline void ExportBufToFile(Buffer&& buf, const std::string& file_path) {
  io::FileOutputStream out(file_path);
  out.Write(buf.data(), buf.size());
}

}  // namespace

// -------------------
// Key Pair Generation
// -------------------

openssl::UniquePkey GenRsaKeyPair(unsigned rsa_keylen) {
  /* EVP_RSA_gen() may be set deprecated by later version of OpenSSL */
  EVP_PKEY* pkey = EVP_PKEY_new();  // placeholder

  openssl::UniquePkeyCtx ctx(
      EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, /* engine = default */ nullptr));
  YACL_ENFORCE(ctx != nullptr);
  OSSL_RET_1(EVP_PKEY_keygen_init(ctx.get()));

  // set key length bits
  OSSL_RET_1(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), rsa_keylen));

  // generate keys
  OSSL_RET_1(EVP_PKEY_keygen(ctx.get(), &pkey));
  return openssl::UniquePkey(pkey);
}

openssl::UniquePkey GenSm2KeyPair() {
  EVP_PKEY* pkey = EVP_PKEY_new();  // placeholder

  openssl::UniquePkeyCtx ctx(
      EVP_PKEY_CTX_new_id(EVP_PKEY_SM2, /* engine = default */ nullptr));
  YACL_ENFORCE(ctx != nullptr);
  OSSL_RET_1(EVP_PKEY_keygen_init(ctx.get()));

  // generate keys
  OSSL_RET_1(EVP_PKEY_keygen(ctx.get(), &pkey));
  return openssl::UniquePkey(pkey);
}

std::pair<Buffer, Buffer> GenRsaKeyPairToPemBuf(unsigned rsa_keygen) {
  auto pkey = GenRsaKeyPair(rsa_keygen);
  Buffer pk_buf = ExportPublicKeyToPemBuf(pkey);
  Buffer sk_buf = ExportSecretKeyToPemBuf(pkey);
  return {pk_buf, sk_buf};
}

std::pair<Buffer, Buffer> GenSm2KeyPairToPemBuf() {
  auto pkey = GenSm2KeyPair();
  Buffer pk_buf = ExportPublicKeyToPemBuf(pkey);
  Buffer sk_buf = ExportSecretKeyToPemBuf(pkey);
  return {pk_buf, sk_buf};
}

// -------------------
// Load Any Format Key
// -------------------

// load pem from buffer
openssl::UniquePkey LoadKeyFromBuf(ByteContainerView buf) {
  // load the buffer to bio
  openssl::UniqueBio bio(BIO_new_mem_buf(buf.data(), buf.size()));

  // create pkey
  EVP_PKEY* pkey = nullptr;

  // decoding, see
  // https://www.openssl.org/docs/manmaster/man7/provider-decoder.html
  auto decoder = openssl::UniqueDecoder(OSSL_DECODER_CTX_new_for_pkey(
      /* EVP_PKEY */ &pkey,
      /* pkey format */ nullptr,     // any format
      /* pkey structure */ nullptr,  // any structure
      /* pkey type */ nullptr,       // any type
      /* selection */ 0,             // auto detect
      /* OSSL_LIB_CTX */ nullptr, /* probquery */ nullptr));

  YACL_ENFORCE(decoder != nullptr, "no decoder found");
  OSSL_RET_1(OSSL_DECODER_from_bio(decoder.get(), bio.get()));

  return openssl::UniquePkey(pkey);
}

openssl::UniquePkey LoadKeyFromFile(const std::string& file_path) {
  return LoadKeyFromBuf(LoadBufFromFile(file_path));
}

// ------------------
// Export PEM Key
// ------------------

// export public key to pem
Buffer ExportPublicKeyToPemBuf(
    /* public key */ const openssl::UniquePkey& pkey) {
  openssl::UniqueBio bio(BIO_new(BIO_s_mem()));  // create an empty bio
  // export certificate to bio
  OSSL_RET_1(PEM_write_bio_PUBKEY(bio.get(), pkey.get()),
             "Failed PEM_export_bio_PUBKEY.");
  return BioToBuf(bio);
}

void ExportPublicKeyToPemFile(const openssl::UniquePkey& pkey,
                              const std::string& file_path) {
  ExportBufToFile(ExportPublicKeyToPemBuf(pkey), file_path);
}

//  export secret key to pem (different from publick key since they may not have
// the same structure)
Buffer ExportSecretKeyToPemBuf(
    /* secret key */ const openssl::UniquePkey& pkey) {
  openssl::UniqueBio bio(BIO_new(BIO_s_mem()));  // create an empty bio

  // export certificate to bio
  OSSL_RET_1(PEM_write_bio_PrivateKey(bio.get(), pkey.get(), nullptr, nullptr,
                                      0, nullptr, nullptr),
             "Failed PEM_export_bio_PrivateKey.");
  return BioToBuf(bio);
}

void ExportSecretKeyToPemBuf(const openssl::UniquePkey& pkey,
                             const std::string& file_path) {
  ExportBufToFile(ExportSecretKeyToPemBuf(pkey), file_path);
}

// ------------------
// Export DER Key
// ------------------

// export public key to pem
Buffer ExportPublicKeyToDerBuf(
    /* public key */ const openssl::UniquePkey& pkey) {
  openssl::UniqueBio bio(BIO_new(BIO_s_mem()));  // create an empty bio
  // export pkey to bio
  auto encoder = openssl::UniqueEncoder(OSSL_ENCODER_CTX_new_for_pkey(
      pkey.get(),
      /* selection: pk and params */ EVP_PKEY_PUBLIC_KEY,
      /* format */ "DER",
      /* RFC 5280: X.509 structure */ "SubjectPublicKeyInfo", nullptr));
  YACL_ENFORCE(encoder != nullptr, "no encoder found");
  OSSL_RET_1(OSSL_ENCODER_to_bio(encoder.get(), bio.get()));
  return BioToBuf(bio);
}

void ExportPublicKeyToDerFile(const openssl::UniquePkey& pkey,
                              const std::string& file_path) {
  ExportBufToFile(ExportPublicKeyToPemBuf(pkey), file_path);
}

//  export secret key to pem (different from publick key since they may not have
// the same structure)
Buffer ExportSecretKeyToDerBuf(
    /* secret key */ const openssl::UniquePkey& pkey) {
  openssl::UniqueBio bio(BIO_new(BIO_s_mem()));  // create an empty bio
  // export pkey to bio
  auto encoder = openssl::UniqueEncoder(OSSL_ENCODER_CTX_new_for_pkey(
      pkey.get(),
      /* selection: pk, sk and params */ EVP_PKEY_KEYPAIR,
      /* format */ "DER",
      /* RFC 5208: PKCS#8 structure */ "PrivateKeyInfo", nullptr));
  YACL_ENFORCE(encoder != nullptr, "no encoder found");
  OSSL_RET_1(OSSL_ENCODER_to_bio(encoder.get(), bio.get()));
  return BioToBuf(bio);
}

void ExportSecretKeyToDerFile(const openssl::UniquePkey& pkey,
                              const std::string& file_path) {
  ExportBufToFile(ExportSecretKeyToPemBuf(pkey), file_path);
}

// -------------------------------
// Gen/Load/Export X509 Certificate
// -------------------------------

openssl::UniqueX509 MakeX509Cert(
    /* issuer's pk */ const openssl::UniquePkey& pk,
    /* issuer's sk */ const openssl::UniquePkey& sk,
    /* subjects info */
    const std::unordered_map<std::string, std::string>& subjects,
    /* time */ unsigned days, HashAlgorithm hash) {
  YACL_ENFORCE(hash == HashAlgorithm::SHA256 || hash == HashAlgorithm::SM3);
  // ++++++++++++++++++++++++++++++
  // Generate X509 cert (version 3)
  // ++++++++++++++++++++++++++++++
  // * Certificate
  //  ** Version Number
  //  ** Serial Number
  //  ** Signature Algorithm ID <= auto filled
  //  ** Issuer Name
  //  ** Validity period
  //  ** Not Before
  //  ** Not After
  //  ** Subject name
  //  ** Subject Public Key Info <= auto filled
  //  ** Public Key Algorithm <= auto filled
  //  ** Subject Public Key
  //  ** Issuer openssl::Unique Identifier (optional)
  //  ** Subject openssl::Unique Identifier (optional)
  //  ** Extensions (optional)
  //  ** ...
  // * Certificate Signature Algorithm
  // * Certificate Signature
  // ++++++++++++++++++++++++++++++
  openssl::UniqueX509 x509(X509_new());
  /* version */
  OSSL_RET_1(X509_set_version(x509.get(), kX509Version));

  /* Serial Number */
  // YACL_ENFORCE(X509_set_serialNumber(x509.get(),
  // ASN1_INTEGER_set_int64(FastRandU64()) == 1);    // set random serial number

  /* time */
  X509_gmtime_adj(X509_get_notBefore(x509.get()), 0);
  X509_gmtime_adj(X509_get_notAfter(x509.get()), days * kSecondsInDay);

  /* setup subject strings */
  // X509_get_subject_name() returns the subject name of certificate x. The
  // returned value is an internal pointer which MUST NOT be freed.
  // see: https://www.openssl.org/docs/man1.1.1/man3/X509_get_subject_name.html
  X509_NAME* name = X509_get_subject_name(x509.get());
  YACL_ENFORCE(name != nullptr);

  for (const auto& field : kX509SubjectFields) {
    auto it = subjects.find(std::string(field));
    YACL_ENFORCE(it != subjects.end(), "Cannot find subject field {}.", field);
    OSSL_RET_1(X509_NAME_add_entry_by_txt(
                   name, it->first.c_str(), MBSTRING_ASC,
                   reinterpret_cast<const unsigned char*>(it->second.c_str()),
                   -1, -1, 0),
               "Set x509 name failed.");
  }

  /* issuer = subject since this cert is self-signed */
  OSSL_RET_1(X509_set_issuer_name(x509.get(), name));

  /* fill cert with rsa public key */
  X509_set_pubkey(x509.get(), pk.get());

  AddX509Extension(x509.get(), NID_basic_constraints, (char*)"CA:TRUE");
  AddX509Extension(x509.get(), NID_subject_key_identifier, (char*)"hash");

  /* self signing with digest algorithm */
  auto sign_bytes = X509_sign(x509.get(), sk.get(),
                              openssl::FetchEvpMd(ToString(hash)).get());
  YACL_ENFORCE(sign_bytes > 0, "Perform self-signing failed.");
  return x509;
}

// load x509 certificate from buffer
openssl::UniqueX509 LoadX509Cert(ByteContainerView buf) {
  // load the buffer to bio
  openssl::UniqueBio bio(BIO_new_mem_buf(buf.data(), buf.size()));

  // bio to x509 [warning]: this may be made deprecated in the future version of
  // OpenSSL, it is recommended to use OSSL_ENCODER and OSSL_DECODER instead.
  auto cert = openssl::UniqueX509(
      PEM_read_bio_X509(/* bio */ bio.get(), /* x509 ptr (optional) */ nullptr,
                        /* password */ nullptr, /* addition */ nullptr));
  YACL_ENFORCE(cert != nullptr, "No X509 from cert generated.");
  return cert;
}

openssl::UniqueX509 LoadX509CertFromFile(const std::string& file_path) {
  return LoadX509Cert(LoadBufFromFile(file_path));
}

// load x509 pk from buffer
openssl::UniquePkey LoadX509CertPublicKeyFromBuf(ByteContainerView buf) {
  auto x509 = LoadX509Cert(buf);
  auto pkey = openssl::UniquePkey(X509_get_pubkey(x509.get()));
  YACL_ENFORCE(pkey != nullptr,
               "Error when reading public key in X509 certificate.");
  return pkey;  // public key only
}

openssl::UniquePkey LoadX509CertPublicKeyFromFile(
    const std::string& file_path) {
  return LoadX509CertPublicKeyFromBuf(LoadBufFromFile(file_path));
}

// export x509 certificate to buffer
Buffer ExportX509CertToBuf(const openssl::UniqueX509& x509) {
  openssl::UniqueBio bio(BIO_new(BIO_s_mem()));  // create an empty bio

  // export certificate to bio
  OSSL_RET_1(PEM_write_bio_X509(bio.get(), x509.get()));

  return BioToBuf(bio);
}

void ExportX509CertToFile(const openssl::UniqueX509& x509,
                          const std::string& file_path) {
  ExportBufToFile(ExportX509CertToBuf(x509), file_path);
}

}  // namespace yacl::crypto
