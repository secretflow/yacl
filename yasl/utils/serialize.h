#pragma once

#include <vector>

#include "yasl/base/buffer.h"
#include "yasl/base/byte_container_view.h"
#include "yasl/base/int128.h"

namespace yasl {

Buffer SerializeArrayOfBuffers(const std::vector<ByteContainerView>& bufs);

std::vector<Buffer> DeserializeArrayOfBuffers(ByteContainerView buf);

Buffer SerializeInt128(int128_t v);

int128_t DeserializeInt128(ByteContainerView buf);

Buffer SerializeUint128(uint128_t v);

uint128_t DeserializeUint128(ByteContainerView buf);

}  // namespace yasl
