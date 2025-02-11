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

#pragma once

#include <set>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "yacl/crypto/hash/ssl_hash.h"
#include "yacl/crypto/hmac/hmac_sha256.h"
#include "yacl/crypto/rand/rand.h"

namespace examples::sse {

class TSet {
 public:
  struct Record {
    std::vector<uint8_t> label;
    std::vector<uint8_t> value;
  };

  TSet(int b, int s, int lambda, int n_lambda);

  static bool AreVectorsEqual(const std::vector<uint8_t>& vec1,
                              const std::vector<uint8_t>& vec2);

  // Pack a pair of vector and string into a single vector
  static std::vector<uint8_t> Pack(
      const std::pair<std::vector<uint8_t>, std::string>& data);
  // Unpack a vector into a pair of vector and string
  static std::pair<std::vector<uint8_t>, std::string> UnPack(
      const std::vector<uint8_t>& packed_data);

  static std::string VectorToString(const std::vector<uint8_t>& vec);

  std::string TSetSetup(
      const std::unordered_map<
          std::string,
          std::vector<std::pair<std::vector<uint8_t>, std::string>>>& T,
      const std::vector<std::string>& keywords);

  // Get the tag for a given keyword
  std::vector<uint8_t> TSetGetTag(const std::string& Kt,
                                  const std::string& w) const;

  // Retrieve records from the TSet
  std::vector<std::pair<std::vector<uint8_t>, std::string>> TSetRetrieve(
      const std::vector<std::vector<Record>>& TSet,
      const std::string& stag) const;

  const std::vector<std::vector<Record>>& GetTSet() const { return tset_; }
  const std::vector<std::set<int>>& GetFree() const { return free_; }

 private:
  void Initialize();

  int b_;
  int s_;
  int lambda_;
  int n_lambda_;
  std::vector<std::vector<Record>> tset_;
  std::vector<std::set<int>> free_;
};

}  // namespace examples::sse
