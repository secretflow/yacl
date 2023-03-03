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

#include <map>

#include "openssl/err.h"
#include "openssl/evp.h"

#include "yacl/crypto/base/ecc/openssl/openssl_group.h"

namespace yacl::crypto::openssl {

static const std::string kLibName = "OpenSSL";

// list openssl supported curves:
//  (shell) >> openssl ecparam -list_curves
// gen this list:
//  (shell) >> openssl ecparam -list_curves | grep ":" | tr '[:upper:]'
//  '[:lower:]' | xargs -L1  | awk -F":" '{s2=$1; gsub("-", "_", s2);
//  printf("{\"%s\", NID_%s},\n", $1, s2)}'
//
// Why there is no NID_X25519, NID_X448, NID_ED25519, NID_ED448 in list?
// In OpenSSL the family of 25519 and 448 crypto-systems is not implemented at
// the "mathematical" EC level, but rather as a high level crypto-system. This
// was by design since they first appeared in OpenSSL as their definition by
// their respective designers is explicitly outside the conventions for
// "traditional" EC curves.
//
// As an example, while the underlying working is definitely based on EC scalar
// multiplication, an X25519 operation is defined as a routine in its spec,
// rather than as a multiplication between a scalar and a point. Things are
// quite similar for the curves used inside Ed*.
//
// That is to say, even though Openssl's EVP_ level API supports Ed*/X* curves,
// the EC_ level API does not.
std::map<CurveName, int> kName2Nid = {
    {"secp112r1", NID_secp112r1},
    {"secp112r2", NID_secp112r2},
    {"secp128r1", NID_secp128r1},
    {"secp128r2", NID_secp128r2},
    {"secp160k1", NID_secp160k1},
    {"secp160r1", NID_secp160r1},
    {"secp160r2", NID_secp160r2},
    {"secp192k1", NID_secp192k1},
    {"secp224k1", NID_secp224k1},
    {"secp224r1", NID_secp224r1},
    {"secp256k1", NID_secp256k1},
    {"secp384r1", NID_secp384r1},
    {"secp521r1", NID_secp521r1},
    {"prime192v1", NID_X9_62_prime192v1},
    {"prime192v2", NID_X9_62_prime192v2},
    {"prime192v3", NID_X9_62_prime192v3},
    {"prime239v1", NID_X9_62_prime239v1},
    {"prime239v2", NID_X9_62_prime239v2},
    {"prime239v3", NID_X9_62_prime239v3},
    {"prime256v1", NID_X9_62_prime256v1},
    {"sect113r1", NID_sect113r1},
    {"sect113r2", NID_sect113r2},
    {"sect131r1", NID_sect131r1},
    {"sect131r2", NID_sect131r2},
    {"sect163k1", NID_sect163k1},
    {"sect163r1", NID_sect163r1},
    {"sect163r2", NID_sect163r2},
    {"sect193r1", NID_sect193r1},
    {"sect193r2", NID_sect193r2},
    {"sect233k1", NID_sect233k1},
    {"sect233r1", NID_sect233r1},
    {"sect239k1", NID_sect239k1},
    {"sect283k1", NID_sect283k1},
    {"sect283r1", NID_sect283r1},
    {"sect409k1", NID_sect409k1},
    {"sect409r1", NID_sect409r1},
    {"sect571k1", NID_sect571k1},
    {"sect571r1", NID_sect571r1},
    {"c2pnb163v1", NID_X9_62_c2pnb163v1},
    {"c2pnb163v2", NID_X9_62_c2pnb163v2},
    {"c2pnb163v3", NID_X9_62_c2pnb163v3},
    {"c2pnb176v1", NID_X9_62_c2pnb176v1},
    {"c2tnb191v1", NID_X9_62_c2tnb191v1},
    {"c2tnb191v2", NID_X9_62_c2tnb191v2},
    {"c2tnb191v3", NID_X9_62_c2tnb191v3},
    {"c2pnb208w1", NID_X9_62_c2pnb208w1},
    {"c2tnb239v1", NID_X9_62_c2tnb239v1},
    {"c2tnb239v2", NID_X9_62_c2tnb239v2},
    {"c2tnb239v3", NID_X9_62_c2tnb239v3},
    {"c2pnb272w1", NID_X9_62_c2pnb272w1},
    {"c2pnb304w1", NID_X9_62_c2pnb304w1},
    {"c2tnb359v1", NID_X9_62_c2tnb359v1},
    {"c2pnb368w1", NID_X9_62_c2pnb368w1},
    {"c2tnb431r1", NID_X9_62_c2tnb431r1},
    {"wap-wsg-idm-ecid-wtls1", NID_wap_wsg_idm_ecid_wtls1},
    {"wap-wsg-idm-ecid-wtls3", NID_wap_wsg_idm_ecid_wtls3},
    {"wap-wsg-idm-ecid-wtls4", NID_wap_wsg_idm_ecid_wtls4},
    {"wap-wsg-idm-ecid-wtls5", NID_wap_wsg_idm_ecid_wtls5},
    {"wap-wsg-idm-ecid-wtls6", NID_wap_wsg_idm_ecid_wtls6},
    {"wap-wsg-idm-ecid-wtls7", NID_wap_wsg_idm_ecid_wtls7},
    {"wap-wsg-idm-ecid-wtls8", NID_wap_wsg_idm_ecid_wtls8},
    {"wap-wsg-idm-ecid-wtls9", NID_wap_wsg_idm_ecid_wtls9},
    {"wap-wsg-idm-ecid-wtls10", NID_wap_wsg_idm_ecid_wtls10},
    {"wap-wsg-idm-ecid-wtls11", NID_wap_wsg_idm_ecid_wtls11},
    {"wap-wsg-idm-ecid-wtls12", NID_wap_wsg_idm_ecid_wtls12},
    {"brainpoolP160t1", NID_brainpoolP160t1},
    {"brainpoolP192r1", NID_brainpoolP192r1},
    {"brainpoolP192t1", NID_brainpoolP192t1},
    {"brainpoolP224r1", NID_brainpoolP224r1},
    {"brainpoolP224t1", NID_brainpoolP224t1},
    {"brainpoolP256r1", NID_brainpoolP256r1},
    {"brainpoolP256t1", NID_brainpoolP256t1},
    {"brainpoolP320r1", NID_brainpoolP320r1},
    {"brainpoolP320t1", NID_brainpoolP320t1},
    {"brainpoolP384r1", NID_brainpoolP384r1},
    {"brainpoolP384t1", NID_brainpoolP384t1},
    {"brainpoolP512r1", NID_brainpoolP512r1},
    {"brainpoolP512t1", NID_brainpoolP512t1},
    {"sm2", NID_sm2},
};

REGISTER_EC_LIBRARY(kLibName, 100, OpensslGroup::IsSupported,
                    OpensslGroup::Create);

std::unique_ptr<EcGroup> OpensslGroup::Create(const CurveMeta &meta) {
  YACL_ENFORCE(kName2Nid.count(meta.LowerName()) > 0,
               "curve {} not supported by openssl", meta.name);
  auto gptr = EC_GROUP_new_by_curve_name(kName2Nid.at(meta.LowerName()));
  // ERR_error_string() is not reentrant, so we can't use it.
  YACL_ENFORCE(
      gptr != nullptr,
      "Openssl create curve group {} fail, nid={}, err code maybe={} (guessed)",
      meta.LowerName(), kName2Nid.at(meta.LowerName()), ERR_get_error());
  return std::unique_ptr<EcGroup>(new OpensslGroup(meta, EC_GROUP_PTR(gptr)));
}

bool OpensslGroup::IsSupported(const CurveMeta &meta) {
  return kName2Nid.count(meta.LowerName()) > 0;
}

std::string OpensslGroup::GetLibraryName() const { return kLibName; }

}  // namespace yacl::crypto::openssl
