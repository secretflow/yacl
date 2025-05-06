// Copyright 2024 Ant Group Co., Ltd.
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

#include <bits/stdc++.h>
#include <emmintrin.h>
#include <openssl/sha.h>

#include <cstdint>
#include <cstring>
#include <iostream>
#include <memory>
#include <random>

#include "yacl/crypto/aes/aes_opt.h"

using uint128_t = __uint128_t;

const uint128_t all_one_uint128_t = ~static_cast<__uint128_t>(0);
const uint128_t select_mask[2] = {0, all_one_uint128_t};

yacl::crypto::AES_KEY scheduled_key[2];

inline uint128_t makeuint128_t(uint64_t high, uint64_t low) {
  return (static_cast<uint128_t>(high) << 64) | low;
}

// generate random uint128_t
uint128_t randomuint128_t() {
  std::random_device rd;
  std::mt19937_64 eng(rd());
  std::uniform_int_distribution<uint64_t> distr;

  uint64_t high = distr(eng);
  uint64_t low = distr(eng);

  return makeuint128_t(high, low);
}

template <int keyLength = 2>
void generateKeys() {
  uint128_t keys[keyLength];

  for (int i = 0; i < keyLength; i++) {
    keys[i] = randomuint128_t();
  }
  AES_opt_key_schedule<keyLength>(keys, scheduled_key);
}

// get the Least Significant Bit of uint128_t
bool getLSB(const uint128_t& x) { return (x & 1) == 1; }

// for encryption and decryption
template <int K, int H>
void myhash(uint128_t* blks) {
  uint128_t tmp[K * H];
  for (int i = 0; i < K * H; ++i) tmp[i] = blks[i];

  ParaEnc<K, H>(tmp, scheduled_key);

  for (int i = 0; i < K * H; ++i) blks[i] = blks[i] ^ tmp[i];
}
// ADN gate half gate optimization
uint128_t GBAND(uint128_t LA0, uint128_t A1, uint128_t LB0, uint128_t B1,
                uint128_t delta, uint128_t* table) {
  bool pa = getLSB(LA0);
  bool pb = getLSB(LB0);

  uint128_t HLA0, HA1, HLB0, HB1;
  uint128_t tmp, W0;
  uint128_t H[4];

  H[0] = LA0;
  H[1] = A1;
  H[2] = LB0;
  H[3] = B1;

  myhash<2, 2>(H);

  HLA0 = H[0];
  HA1 = H[1];
  HLB0 = H[2];
  HB1 = H[3];

  table[0] = HLA0 ^ HA1;
  table[0] = table[0] ^ (select_mask[pb] & delta);

  W0 = HLA0;
  W0 = W0 ^ (select_mask[pa] & table[0]);

  tmp = HLB0 ^ HB1;
  table[1] = tmp ^ LA0;

  W0 = W0 ^ HLB0;
  W0 = W0 ^ (select_mask[pb] & tmp);
  return W0;
}

// garble process
void GB(std::string* circuits, int length, uint128_t& R, uint128_t* F,
        uint128_t* e, uint128_t& gate_wires, bool& d) {
  R = randomuint128_t();
  R = R | 1;  // ensure the LSB of R is 1

  for (int i = 0; i < length; i++) {
    if (circuits[i].find("input") != std::string ::npos)
      e[i] = randomuint128_t();
    else {
      gate_wires = GBAND(e[0], e[0] ^ R, e[1], e[1] ^ R, R, F);
      d = getLSB(gate_wires);
    }
  }
}

// encoding process
void EN(bool a, bool b, uint128_t* e,
        std::unordered_map<std::string, uint128_t>& buffer, uint128_t R) {
  buffer["alice"] = e[0] ^ (select_mask[a] & R);
  buffer["bob"] = e[1] ^ (select_mask[b] & R);
}

// evaluate process
uint128_t* EV(std::unordered_map<std::string, uint128_t>& buffer) {
  uint128_t A = buffer["alice"], B = buffer["bob"];

  uint128_t HA, HB, W;
  int sa, sb;

  sa = getLSB(A);
  sb = getLSB(B);
  uint128_t H[2];

  H[0] = A;
  H[1] = B;

  myhash<2, 1>(H);

  HA = H[0];
  HB = H[1];

  W = HA ^ HB;
  W = W ^ (select_mask[sa] & buffer["table0"]);
  W = W ^ (select_mask[sb] & buffer["table1"]);
  W = W ^ (select_mask[sb] & A);

  buffer["AND"] = W;
}

int main() {
  bool a, b;
  std::cout << "Please input the value：" << std::endl;
  std::cin >> a >> b;

  std::string circuits[3] = {"input1", "input2", "outputAND"};
  int length = 3;
  uint128_t e[2];        // circuits garble value of input for encoding
  uint128_t gate_wires;  // circuits garble value of gate output
  bool d;                // value for decoding
  uint128_t F[2];        // two half gates
  uint128_t R;           // delta in gc
  std::unordered_map<std::string, uint128_t>
      buffer;  // simulate the communication process

  generateKeys();
  // step 1: generate the garble circuits
  GB(circuits, length, R, F, e, gate_wires, d);
  // step 2：encoding the inputs
  EN(a, b, e, buffer, R);

  // simulate the communication of garble table
  buffer["table0"] = F[0];
  buffer["table1"] = F[1];

  // step 3: evaluation
  EV(buffer);
  // step 4: decoding the result
  std::cout << a << " and " << b << " = " << (getLSB(buffer["AND"]) ^ d)
            << std::endl;

  return 0;
}
