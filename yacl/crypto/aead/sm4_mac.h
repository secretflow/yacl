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

#include <vector>

#include "yacl/base/byte_container_view.h"
#include "yacl/secparam.h"

/* submodules */
#include "yacl/crypto/block_cipher/symmetric_crypto.h"
#include "yacl/crypto/hash/ssl_hash.h"
#include "yacl/crypto/hmac/hmac_sm3.h"

/* security parameter declaration */
YACL_MODULE_DECLARE("sm4_mac", SecParam::C::k128, SecParam::S::INF);

namespace yacl::crypto {

// SM4-CTR based MAC then Encryption(Mte). Hmac-sm3 is used as MAC algorithm
// here.

// Input:
// - key: sm4 ctr key
// - iv: initial vector
// - plaintext: plaintext to be encrypted
//
// Output:
// - ciphertext: the encryption of (hmac || plaintext) using SM4-CTR
std::vector<uint8_t> Sm4MteEncrypt(ByteContainerView key, ByteContainerView iv,
                                   ByteContainerView plaintext);

// SM envelope open with sm4-ctr + hmac-sm3 + sm2.
//
// Input:
// - key: sm2 ctr key
// - iv: initial vector
// - ciphertext: the encrypted (hmac || plaintext) using SM4-CTR
//
// Output:
// - plaintext: the decryption of ciphertext using SM4-CTR
std::vector<uint8_t> Sm4MteDecrypt(ByteContainerView key, ByteContainerView iv,
                                   ByteContainerView ciphertext);

}  // namespace yacl::crypto
