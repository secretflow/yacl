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

#pragma once

#include <unordered_map>
#include <set>
#include <utility>
#include <string>
#include <vector>

#include "yacl/crypto/hash/ssl_hash.h"
#include "yacl/crypto/hmac/hmac_sha256.h"
#include "yacl/crypto/rand/rand.h"



namespace yacl::crypto::primitives::sse {

class TSet {
 public:
  struct Record {
    std::vector<uint8_t> label;  // 存储长度为 λ 的位字符串
    std::vector<uint8_t> value;  // 存储长度为 n(λ) + 1 的位字符串
  };

  TSet(int B, int S, int lambda, int n_lambda);

  bool areVectorsEqual(const std::vector<uint8_t>& vec1,
                       const std::vector<uint8_t>& vec2) const;

  std::vector<uint8_t> pack(
      const std::pair<std::vector<uint8_t>, std::string>& data) const;

  std::pair<std::vector<uint8_t>, std::string> unpack(
      const std::vector<uint8_t>& packed_data) const;

  std::string vectorToString(const std::vector<uint8_t>& vec) const;

  std::pair<std::vector<std::vector<Record>>, std::string> TSetSetup(
      const std::unordered_map<
          std::string,
          std::vector<std::pair<std::vector<uint8_t>, std::string>>>& T,
      const std::vector<std::string>& keywords);

  std::vector<uint8_t> TSetGetTag(const std::string& Kt,
                                  const std::string& w) const;

  std::vector<std::pair<std::vector<uint8_t>, std::string>> TSetRetrieve(
      const std::vector<std::vector<Record>>& TSet,
      const std::string& stag) const;

  // 公共接口函数，用于访问私有成员变量
  const std::vector<std::vector<Record>>& getTSet() const { return TSet_; }
  const std::vector<std::set<int>>& getFree() const { return Free_; }

 private:
  void initialize();

  int B_;
  int S_;
  int lambda_;
  int n_lambda_;
  std::vector<std::vector<Record>> TSet_;
  std::vector<std::set<int>> Free_;
};

}  // namespace yacl::crypto::primitives::sse
