// Copyright 2023 Ant Group Co., Ltd.
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

namespace yacl::crypto {

// Linear code interface in F2k
class LinearCodeInterface {
 public:
  LinearCodeInterface(const LinearCodeInterface &) = delete;
  LinearCodeInterface &operator=(const LinearCodeInterface &) = delete;
  LinearCodeInterface() = default;
  virtual ~LinearCodeInterface() = default;

  // Get the dimention / length
  virtual uint32_t GetDimention() const = 0;
  virtual uint32_t GetLength() const = 0;

  // (maybe randomly) Generate generator matrix
  // virtual void GenGenerator() const = 0;
};

}  // namespace yacl::crypto
