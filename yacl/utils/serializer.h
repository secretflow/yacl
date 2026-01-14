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

#pragma once

#include <cstdlib>
#include <type_traits>

#include "msgpack.hpp"

#include "yacl/base/buffer.h"
#include "yacl/base/byte_container_view.h"
#include "yacl/io/msgpack/buffer.h"

namespace yacl {

// Serialization/deserialization tools,
// supporting a single variable or a set of variables.
//
//
// Use case 1: Serialize a single variable
//
// > int64_t v1 = -12345;
// > auto buf = SerializeVars(v1);
// > int64_t v1_new = DeserializeVars<int64_t>(buf);
//
//
// Use case 2: Serialize multiple variables
//
// > int64_t v1 = -12345;
// > bool v2 = true;
// > std::string v3 = "hello";
// >
// > auto buf = SerializeVars(v1, v2, v3);
// > auto [v1_new, v2_new, v3_new] =
// >     DeserializeVars<int64_t, bool, std::string>(buf);
//
//
// Use case 3: Deserialize to an existing variable, avoiding memory copy
//
// > int64_t v1 = 123;
// > std::vector<std::string> v2 = {"hello", "world"};
// >
// > auto needed_buf_size = SerializeVarsTo(nullptr, 0, v1, v2);
// > ... get a buffer larger than needed_buf_size
// > SerializeVarsTo(buffer, needed_buf_size, v1, v2);
// >
// > int64_t v1_new;
// > std::vector<std::string> v2_new;
// > DeserializeVarsTo(buffer, &v1_new, &v2_new);
//
//
// Special notice:
// If you need to serialize special types (non-STL types/containers),
// such as int128_t, please include the following header file to enable support
// for extended types:
// > #include "yacl/utils/serializer_adapter.h"

template <typename... Ts>
inline yacl::Buffer SerializeVars(const Ts &...obj) {
  yacl::Buffer buf;
  yacl::io::StreamBuffer sbuf(&buf);
  (..., msgpack::pack(sbuf, obj));
  return buf;
}

// Serialize the 'obj' into buf and return the actual number of bytes written.
// If buf is empty, only calculate the size of the serialized object.
template <typename... Ts>
inline size_t SerializeVarsTo(uint8_t *buf, size_t buf_len, const Ts &...obj) {
  if (buf == nullptr) {
    yacl::io::ShadowBuffer sd_buf;
    (..., msgpack::pack(sd_buf, obj));
    return sd_buf.GetDataSize();
  }

  yacl::io::FixedBuffer fbuf((char *)buf, buf_len);
  (..., msgpack::pack(fbuf, obj));
  return fbuf.WrittenSize();
}

namespace internal {

inline bool ref_or_copy(msgpack::type::object_type, std::size_t, void *) {
  // Always use reference mode to avoid pointers pointing to illegal addresses.
  return true;
}

template <typename... Ts, std::size_t... Is>
std::tuple<Ts...> DoDeserializeAsTuple(std::index_sequence<Is...>,
                                       yacl::ByteContainerView in) {
  std::size_t off = 0;
  std::tuple<Ts...> res;
  (..., msgpack::unpack(reinterpret_cast<const char *>(in.data()), in.size(),
                        off, ref_or_copy)
            ->convert(std::get<Is>(res)));

  return res;
}

}  // namespace internal

// If Ts is a single type, return type T
// If Ts is a type array, return std::tuple<Ts...>
template <typename... Ts>
inline auto DeserializeVars(yacl::ByteContainerView in) ->
    typename std::conditional_t<sizeof...(Ts) == 1,
                                std::tuple_element_t<0, std::tuple<Ts...>>,
                                std::tuple<Ts...>> {
  if constexpr (sizeof...(Ts) == 1) {
    auto msg = msgpack::unpack(reinterpret_cast<const char *>(in.data()),
                               in.size(), internal::ref_or_copy);

    std::tuple_element_t<0, std::tuple<Ts...>> res;
    msg->convert(res);
    return res;
  } else {
    return internal::DoDeserializeAsTuple<Ts...>(
        std::index_sequence_for<Ts...>(), in);
  }
}

template <typename... Ts>
inline size_t DeserializeVarsTo(yacl::ByteContainerView in, Ts *...vars) {
  std::size_t off = 0;
  (..., msgpack::unpack(reinterpret_cast<const char *>(in.data()), in.size(),
                        off, internal::ref_or_copy)
            ->convert(*vars));
  return off;
}

}  // namespace yacl
