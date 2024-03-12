// Copyright 2024 Ant Group Co., Ltd.
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

#include "yacl/utils/serializer.h"

namespace yacl {

bool internal::ref_or_copy(msgpack::type::object_type type, std::size_t length,
                           void *) {
  switch (type) {
    case msgpack::type::STR:
      // Small strings are copied.
      return length >= 32;
    case msgpack::type::BIN:
      // BIN is always referenced.
      return true;
    case msgpack::type::EXT:
      // EXT is always copied.
      return false;
    default:
      YACL_THROW("unexpected type {}", static_cast<int>(type));
  }
}

}  // namespace yacl
