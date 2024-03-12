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

#include "yacl/base/int128.h"
#include "yacl/utils/serializer.h"

// clang-format off
namespace msgpack {
MSGPACK_API_VERSION_NAMESPACE(MSGPACK_DEFAULT_API_NS) {
namespace adaptor {
  // clang-format on

  //===   adapter of int128_t ===//

  template <>
  struct pack<int128_t> {
    template <typename Stream>
    packer<Stream> &operator()(msgpack::packer<Stream> &o,
                               const int128_t &v) const {
      std::pair<int64_t, uint64_t> pair = yacl::DecomposeInt128(v);
      o.pack(pair);
      return o;
    }
  };

  template <>
  struct convert<int128_t> {
    const msgpack::object &operator()(const msgpack::object &o,
                                      int128_t &v) const {
      auto pair = o.as<std::pair<int64_t, uint64_t>>();
      v = yacl::MakeInt128(pair.first, pair.second);
      return o;
    }
  };

  //===   adapter of uint128_t ===//

  template <>
  struct pack<uint128_t> {
    template <typename Stream>
    packer<Stream> &operator()(msgpack::packer<Stream> &o,
                               const uint128_t &v) const {
      std::pair<uint64_t, uint64_t> pair = yacl::DecomposeUInt128(v);
      o.pack(pair);
      return o;
    }
  };

  template <>
  struct convert<uint128_t> {
    const msgpack::object &operator()(const msgpack::object &o,
                                      uint128_t &v) const {
      auto pair = o.as<std::pair<uint64_t, uint64_t>>();
      v = yacl::MakeUint128(pair.first, pair.second);
      return o;
    }
  };

  //===   adapter of ByteContainerView ===//

  template <>
  struct pack<yacl::ByteContainerView> {
    template <typename Stream>
    packer<Stream> &operator()(msgpack::packer<Stream> &o,
                               const yacl::ByteContainerView &v) const {
      uint32_t size = checked_get_container_size(v.size());
      o.pack_bin(size);
      o.pack_bin_body(reinterpret_cast<const char *>(v.data()), size);
      return o;
    }
  };

  // If you deserialize into ByteContainerView, you can avoid copying, but
  // ownership depends on the input buffer.
  template <>
  struct convert<yacl::ByteContainerView> {
    const msgpack::object &operator()(const msgpack::object &o,
                                      yacl::ByteContainerView &v) const {
      YACL_ENFORCE(o.type == msgpack::type::BIN,
                   "Type mismatch, cannot deserialize. exp_type={}",
                   static_cast<int>(o.type));
      v = yacl::ByteContainerView(o.via.bin.ptr, o.via.bin.size);
      return o;
    }
  };

  //===   adapter of yacl::Buffer ===//

  // yacl::Buffer is compatible with yacl::ByteContainerView
  template <>
  struct pack<yacl::Buffer> {
    template <typename Stream>
    packer<Stream> &operator()(msgpack::packer<Stream> &o,
                               const yacl::Buffer &v) const {
      uint32_t size = checked_get_container_size(v.size());
      o.pack_bin(size);
      o.pack_bin_body(v.data<char>(), size);
      return o;
    }
  };

  template <>
  struct convert<yacl::Buffer> {
    const msgpack::object &operator()(const msgpack::object &o,
                                      yacl::Buffer &v) const {
      YACL_ENFORCE(o.type == msgpack::type::BIN,
                   "Type mismatch, cannot deserialize. ");
      v = yacl::Buffer(reinterpret_cast<const void *>(o.via.bin.ptr),
                       o.via.bin.size);
      return o;
    }
  };

  // clang-format off
}  // namespace adaptor
}  // namespace msgpack
}  // namespace msgpack
// clang-format on
