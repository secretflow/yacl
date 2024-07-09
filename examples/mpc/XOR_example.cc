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

using namespace std;
using namespace yacl::crypto;
using uint128_t = __uint128_t;

const uint128_t all_one_uint128_t = ~static_cast<__uint128_t>(0);
const uint128_t select_mask[2] = {0, all_one_uint128_t};

constexpr uint8_t key[16] = {0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
                             0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C};

inline uint128_t makeuint128_t(uint64_t high, uint64_t low) {
  return (static_cast<uint128_t>(high) << 64) | low;
}

// generate uint128_t
uint128_t randomuint128_t() {
  std::random_device rd;
  std::mt19937_64 eng(rd());
  std::uniform_int_distribution<uint64_t> distr;

  uint64_t high = distr(eng);
  uint64_t low = distr(eng);

  return makeuint128_t(high, low);
}

// get the Least Significant Bit of uint128_t
bool getLSB(const uint128_t& x) { return (x & 1) == 1; }

// for encryption and decryption
template <int K, int H>
void myhash(uint128_t* blks) {
  uint128_t key_uint128_t;
  AES_KEY aes_key;
  memcpy(&key_uint128_t, key, sizeof(key_uint128_t));
  AES_set_encrypt_key(key_uint128_t, &aes_key);

  uint128_t tmp[K * H];
  for (int i = 0; i < K * H; ++i) tmp[i] = blks[i];

  ParaEnc<K, H>(tmp, &aes_key);

  for (int i = 0; i < K * H; ++i) blks[i] = blks[i] ^ tmp[i];
}

// garble process
void GB(string* circuits, int length, uint128_t& R, uint128_t* e,
        uint128_t& gate_wires, bool& d) {
  R = randomuint128_t();
  R = R | 1;  // ensure the LSB of R is 1

  for (int i = 0; i < length; i++) {
    if (circuits[i].find("input") != string ::npos)
      e[i] = randomuint128_t();
    else {
      gate_wires = e[0] ^ e[1];
      d = getLSB(gate_wires);
    }
  }
}

// encoding process
void EN(bool a, bool b, uint128_t* e, unordered_map<string, uint128_t>& buffer,
        uint128_t R) {
  buffer["alice"] = e[0] ^ (select_mask[a] & R);
  buffer["bob"] = e[1] ^ (select_mask[b] & R);
}

// evaluate process
uint128_t* EV(unordered_map<string, uint128_t>& buffer) {
  uint128_t A = buffer["alice"], B = buffer["bob"];
  buffer["XOR"] = A ^ B;
}

int main() {
  bool a, b;
  cout << "Please input the value：" << endl;
  cin >> a >> b;

  string circuits[3] = {"input1", "input2", "outputXOR"};
  int length = 3;
  uint128_t e[2];        // circuits garble value of input for encoding
  uint128_t gate_wires;  // circuits garble value of gate output
  bool d;                // value for decoding
  uint128_t R;           // delta in gc
  unordered_map<string, uint128_t>
      buffer;  // simulate the communication process

  // step 1: generate the garble circuits
  GB(circuits, length, R, e, gate_wires, d);
  // step 2：encoding the inputs
  EN(a, b, e, buffer, R);
  // step 3: evaluation
  EV(buffer);
  // step 4: decoding the result
  cout << a << " xor " << b << " = " << (getLSB(buffer["XOR"]) ^ d) << endl;

  return 0;
}
