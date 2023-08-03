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

#pragma once

namespace yacl {

// borrow from c++20 stl
enum class Endian {
  // The high byte of the data is stored in the high address of the memory
  little = __ORDER_LITTLE_ENDIAN__,
  // The high byte of the data is stored in the low address of the memory
  big = __ORDER_BIG_ENDIAN__,
  // Auto-detect the endianness of the current machine
  native = __BYTE_ORDER__,  // alias for little or big
};

}  // namespace yacl
