// Copyright 2022 Ant Group Co., Ltd.
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

#include "yacl/base/buffer.h"
#include "yacl/base/byte_container_view.h"
#include "yacl/base/int128.h"
#include "yacl/utils/serializer.h"
#include "yacl/utils/serializer_adapter.h"

namespace yacl {

// deprecated. please call SerializeVars(...) directly
inline Buffer SerializeArrayOfBuffers(
    const std::vector<ByteContainerView>& bufs) {
  return SerializeVars(bufs);
}

// deprecated. please call DeserializeVars(...) directly
inline std::vector<Buffer> DeserializeArrayOfBuffers(ByteContainerView buf) {
  return DeserializeVars<std::vector<Buffer>>(buf);
}

// deprecated. please call SerializeVars(...) directly
inline Buffer SerializeInt128(int128_t v) { return SerializeVars(v); }

// deprecated. please call DeserializeVars(...) directly
inline int128_t DeserializeInt128(ByteContainerView buf) {
  return DeserializeVars<int128_t>(buf);
}

// deprecated. please call SerializeVars(...) directly
inline Buffer SerializeUint128(uint128_t v) { return SerializeVars(v); }

// deprecated. please call DeserializeVars(...) directly
inline uint128_t DeserializeUint128(ByteContainerView buf) {
  return DeserializeVars<uint128_t>(buf);
}

}  // namespace yacl
