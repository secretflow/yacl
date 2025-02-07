// Copyright 2024 Li Zhihang.
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

#include "yacl/examples/sse/tset.h"

namespace examples::sse {

TSet::TSet(int b, int s, int lambda, int n_lambda)
    : b_(b), s_(s), lambda_(lambda), n_lambda_(n_lambda) {
  Initialize();
}

bool TSet::AreVectorsEqual(const std::vector<uint8_t>& vec1,
                           const std::vector<uint8_t>& vec2) const {
  return std::equal(vec1.begin(), vec1.end(), vec2.begin(), vec2.end());
}

std::vector<uint8_t> TSet::Pack(
    const std::pair<std::vector<uint8_t>, std::string>& data) const {
  const auto& first = data.first;
  const auto& second = data.second;

  std::vector<uint8_t> result;

  // 1. add the first part (a vector<uint8_t> with 9 bytes)
  result.insert(result.end(), first.begin(), first.end());

  // 2. add the length of the second part (4 bytes)
  uint32_t second_length = static_cast<uint32_t>(second.size());
  uint8_t length_bytes[4];
  std::memcpy(length_bytes, &second_length, 4);
  result.insert(result.end(), length_bytes, length_bytes + 4);

  // 3. add the second part (a string)
  result.insert(result.end(), second.begin(), second.end());

  return result;
}

std::pair<std::vector<uint8_t>, std::string> TSet::UnPack(
    const std::vector<uint8_t>& packed_data) const {
  // 1. extract the first part (9 bytes)
  std::vector<uint8_t> first(packed_data.begin(), packed_data.begin() + 9);

  // 2. extract the length of the second part (4 bytes)
  uint32_t second_length = 0;
  std::memcpy(&second_length, packed_data.data() + 9, 4);

  // 3. extract the second part (a string)
  std::string second(packed_data.begin() + 13,
                     packed_data.begin() + 13 + second_length);

  return {first, second};
}

std::string TSet::VectorToString(const std::vector<uint8_t>& vec) const {
  std::string result;
  for (auto& byte : vec) {
    result += std::to_string(static_cast<int>(byte));
  }
  return result;
}

void TSet::Initialize() {
  tset_.resize(b_, std::vector<Record>(s_));
  free_.resize(b_);
  for (int i = 0; i < b_; ++i) {
    for (int j = 1; j <= s_; ++j) {
      free_[i].insert(j);
    }
  }

  for (int i = 0; i < b_; ++i) {
    for (int j = 0; j < s_; ++j) {
      tset_[i][j].label.resize(lambda_ / 8, 0);
      tset_[i][j].value.resize(n_lambda_ / 8 + 1, 0);
    }
  }
}

std::pair<std::vector<std::vector<TSet::Record>>, std::string> TSet::TSetSetup(
    const std::unordered_map<
        std::string, std::vector<std::pair<std::vector<uint8_t>, std::string>>>&
        T,
    const std::vector<std::string>& keywords) {
  std::vector<std::vector<Record>> TSet;
  std::vector<std::set<int>> Free;

restart:
  Initialize();

  std::vector<uint8_t> rand_bytes_Kt = yacl::crypto::RandBytes(32);
  std::string Kt = VectorToString(rand_bytes_Kt);
  yacl::crypto::HmacSha256 hmac_F_line_Tset(Kt);
  for (const auto& keyword : keywords) {
    hmac_F_line_Tset.Reset();
    hmac_F_line_Tset.Update(keyword);
    auto mac = hmac_F_line_Tset.CumulativeMac();
    std::string stag = VectorToString(mac);
    const auto& t = T.find(keyword)->second;
    yacl::crypto::HmacSha256 hmac_F_Tset(stag);
    size_t i = 1;
    for (const auto& si : t) {
      hmac_F_Tset.Reset();
      hmac_F_Tset.Update(std::to_string(i));
      auto mac = hmac_F_Tset.CumulativeMac();
      std::string mac_str = VectorToString(mac);

      yacl::crypto::Sm3Hash sm3;
      sm3.Reset();
      std::vector<uint8_t> hash = sm3.Update(mac_str).CumulativeHash();
      size_t hash_value = 0;
      for (size_t i = 0; i < hash.size(); ++i) {
        hash_value = (hash_value * 256 + hash[i]) % b_;
      }
      size_t b = (hash_value % b_);
      std::vector<uint8_t> L(hash.begin(), hash.begin() + lambda_ / 8);
      yacl::crypto::Sha256Hash sha256;
      sha256.Reset();
      std::vector<uint8_t> K = sha256.Update(mac_str).CumulativeHash();
      if (free_[b].empty()) {
        goto restart;
      }

      auto it = free_[b].begin();
      std::advance(it, yacl::crypto::RandU32() % free_[b].size());
      int j = *it;
      free_[b].erase(j);

      j = (j - 1) % s_;
      tset_[b][j].label = L;

      auto packed_si = Pack(si);
      size_t beta = (i < t.size()) ? 1 : 0;
      std::vector<uint8_t> beta_si;
      beta_si.push_back(static_cast<uint8_t>(beta));
      beta_si.insert(beta_si.end(), packed_si.begin(), packed_si.end());
      std::vector<uint8_t> value_xor_k(beta_si.size());
      for (size_t k = 0; k < beta_si.size(); ++k) {
        value_xor_k[k] = beta_si[k] ^ K[k % K.size()];
      }
      tset_[b][j].value = value_xor_k;
      i++;
    }
  }

  return {tset_, Kt};
}

std::vector<uint8_t> TSet::TSetGetTag(const std::string& Kt,
                                      const std::string& w) const {
  yacl::crypto::HmacSha256 hmac_F_line_Tset(Kt);
  hmac_F_line_Tset.Reset();
  hmac_F_line_Tset.Update(w);
  auto mac = hmac_F_line_Tset.CumulativeMac();
  return mac;
}

std::vector<std::pair<std::vector<uint8_t>, std::string>> TSet::TSetRetrieve(
    const std::vector<std::vector<Record>>& tset,
    const std::string& stag) const {
  yacl::crypto::HmacSha256 hmac_F_Tset(stag);

  std::vector<std::pair<std::vector<uint8_t>, std::string>> t;
  uint8_t beta = 1;
  size_t i = 1;

  while (beta == 1) {
    hmac_F_Tset.Reset();
    hmac_F_Tset.Update(std::to_string(i));
    auto mac = hmac_F_Tset.CumulativeMac();
    std::string mac_str = VectorToString(mac);

    yacl::crypto::Sm3Hash sm3;
    sm3.Reset();
    std::vector<uint8_t> hash = sm3.Update(mac_str).CumulativeHash();
    size_t hash_value = 0;
    for (size_t i = 0; i < hash.size(); ++i) {
      hash_value = (hash_value * 256 + hash[i]) % b_;
    }
    size_t b = (hash_value % b_);

    std::vector<uint8_t> L(hash.begin(), hash.begin() + lambda_ / 8);
    yacl::crypto::Sha256Hash sha256;
    sha256.Reset();
    std::vector<uint8_t> K = sha256.Update(mac_str).CumulativeHash();
    auto& B = tset[b];
    int j = 0;
    for (; j < s_; ++j) {
      if (AreVectorsEqual(B[j].label, L)) {
        std::vector<uint8_t> v(B[j].value.size());
        for (size_t k = 0; k < v.size(); ++k) {
          v[k] = B[j].value[k] ^ K[k % K.size()];
        }
        // Let β be the first bit of v, and s the remaining n(λ) bits of v
        beta = v[0];
        std::vector<uint8_t> s(v.begin() + 1, v.end());
        auto unpacked_s = UnPack(s);
        t.push_back(unpacked_s);
      }
    }
    ++i;
    if (i > 100) {
      break;
    }
  }

  return t;
}

}  // namespace examples::sse
