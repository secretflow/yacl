// Copyright 2024 Guowei Ling.
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

#include "examples/hesm2/ciphertext.h"
#include "examples/hesm2/private_key.h"

namespace examples::hesm2 {

struct DecryptResult {
  yacl::math::MPInt m;
  bool success;
};

Ciphertext Encrypt(const yacl::math::MPInt& message, const PublicKey& pk);

DecryptResult Decrypt(const Ciphertext& ciphertext, const PrivateKey& sk);

DecryptResult ParDecrypt(const Ciphertext& ciphertext, const PrivateKey& sk);

Ciphertext HAdd(const Ciphertext& ciphertext1, const Ciphertext& ciphertext2,
                const PublicKey& pk);

Ciphertext HSub(const Ciphertext& ciphertext1, const Ciphertext& ciphertext2,
                const PublicKey& pk);

Ciphertext HMul(const Ciphertext& ciphertext1, const yacl::math::MPInt& scalar,
                const PublicKey& pk);

}  // namespace examples::hesm2