#include "yasl/utils/serialize.h"

#include "yasl/utils/serializable.pb.h"

namespace yasl {

Buffer SerializeArrayOfBuffers(const std::vector<ByteContainerView>& bufs) {
  ArrayOfBuffer proto;
  for (const auto& b : bufs) {
    proto.add_bufs(b.data(), b.size());
  }
  Buffer b(proto.ByteSizeLong());
  proto.SerializePartialToArray(b.data(), b.size());
  return b;
}

std::vector<Buffer> DeserializeArrayOfBuffers(ByteContainerView buf) {
  ArrayOfBuffer proto;
  std::vector<Buffer> bufs;
  proto.ParseFromArray(buf.data(), buf.size());
  for (const auto& b : proto.bufs()) {
    bufs.emplace_back(b);
  }
  return bufs;
}

Buffer SerializeInt128(int128_t v) {
  Int128Proto proto;
  auto parts = DecomposeInt128(v);
  proto.set_hi(parts.first);
  proto.set_lo(parts.second);

  Buffer b(proto.ByteSizeLong());
  proto.SerializePartialToArray(b.data(), b.size());
  return b;
}

int128_t DeserializeInt128(ByteContainerView buf) {
  Int128Proto proto;
  proto.ParseFromArray(buf.data(), buf.size());
  return MakeInt128(proto.hi(), proto.lo());
}

Buffer SerializeUint128(uint128_t v) {
  Uint128Proto proto;
  auto parts = DecomposeUInt128(v);
  proto.set_hi(parts.first);
  proto.set_lo(parts.second);

  Buffer b(proto.ByteSizeLong());
  proto.SerializePartialToArray(b.data(), b.size());
  return b;
}

uint128_t DeserializeUint128(ByteContainerView buf) {
  Uint128Proto proto;
  proto.ParseFromArray(buf.data(), buf.size());
  return MakeUint128(proto.hi(), proto.lo());
}

}  // namespace yasl
