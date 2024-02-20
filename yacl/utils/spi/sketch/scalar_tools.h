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

#include "msgpack.hpp"

#include "yacl/io/msgpack/buffer.h"
#include "yacl/io/msgpack/spec_traits.h"
#include "yacl/utils/spi/item.h"

namespace yacl {

// Who are using those tools?
// - galois field SPI (YACL)
// - HE SPI (HEU)

class ScalarSketchTools {
 public:
  // ===  THE MSGPACK SERIALIZE FORMAT === //
  // | 1bytes header (optional) | body |
  // header: an uint7 number (0~127)
  // body: depends on if item is an array
  // - Scalar: |STR len| serialized buffer |
  // - Vector: |ARRAY len|STR len|element-1 buf|STR len|element-2 buf|...

  template <typename T, int&... ExplicitArgumentBarrier, typename this_t>
  static Buffer Serialize(this_t* this_ptr, const Item& x, int8_t header = -1) {
    Buffer buf;
    io::StreamBuffer sbuf(&buf);
    msgpack::packer<io::StreamBuffer> packer(sbuf);

    if (x.IsArray()) {
      auto xsp = x.AsSpan<T>();
      if (xsp.empty()) {
        if (header >= 0) {
          packer.pack_int8(header);
        }
        packer.pack_array(0);
        return buf;
      }

      // reserve space and pack header
      // we predict total size based on item[0]
      auto item_size = this_ptr->Serialize(xsp[0], nullptr, 0) + 5;
      sbuf.Expand(item_size * xsp.length() * 1.1);
      if (header >= 0) {
        packer.pack_int8(header);
      }
      packer.pack_array(xsp.length());

      // todo: need parallel
      size_t total_sz = 0;
      for (size_t i = 0; i < xsp.length(); ++i) {
        auto body_sz = this_ptr->Serialize(xsp[i], nullptr, 0);
        total_sz += body_sz;
        packer.pack_str(body_sz);
        if (sbuf.FreeSize() < body_sz) {
          size_t exp_size = (total_sz / (i + 1) + 5) * (xsp.length() - i);
          sbuf.Expand(std::max(exp_size, body_sz));
        }
        body_sz = this_ptr->Serialize(
            xsp[i], reinterpret_cast<uint8_t*>(sbuf.PosLoc()), sbuf.FreeSize());
        sbuf.IncPos(body_sz);
      }
      return buf;
    } else {
      auto& xt = x.As<T>();
      auto sz = this_ptr->Serialize(xt, nullptr, 0);
      sbuf.Expand(sz + yacl::io::msgpack_traits::HeadSizeOfStr(sz) + 1);
      // pack optional header
      if (header >= 0) {
        packer.pack_int8(header);
      }
      packer.pack_str(sz);  // pack str len
      // write payload
      auto body_sz = this_ptr->Serialize(
          xt, reinterpret_cast<uint8_t*>(sbuf.PosLoc()), sbuf.FreeSize());
      sbuf.IncPos(body_sz);
      return buf;
    }
  }

  // serialize field element(s) to already allocated buffer.
  // if buf is nullptr, then calc approximate serialize size only
  // @return: the actual size of serialized buffer
  template <typename T, int&... ExplicitArgumentBarrier, typename this_t>
  static size_t Serialize(this_t* this_ptr, const Item& x, uint8_t* buf,
                          size_t buf_len, int8_t header = -1) {
    // just calc size
    if (buf == nullptr) {
      size_t header_len = header >= 0 ? 1 : 0;
      if (x.IsArray()) {
        auto xsp = x.AsSpan<T>();
        std::atomic<size_t> totel_len =
            yacl::io::msgpack_traits::HeadSizeOfArray(xsp.length());
        yacl::parallel_for(0, xsp.length(), [&](int64_t beg, int64_t end) {
          for (int64_t i = beg; i < end; ++i) {
            auto body_sz = this_ptr->Serialize(xsp[i], nullptr, 0);
            totel_len +=
                (body_sz + yacl::io::msgpack_traits::HeadSizeOfStr(body_sz));
          }
        });
        return totel_len + header_len;
      } else {  // scalar case
        auto& xt = x.As<T>();
        auto body_sz = this_ptr->Serialize(xt, nullptr, 0);
        return body_sz + yacl::io::msgpack_traits::HeadSizeOfStr(body_sz) +
               header_len;
      }
    }

    // actual pack
    yacl::io::FixedBuffer sbuf(reinterpret_cast<char*>(buf), buf_len);
    msgpack::packer<yacl::io::FixedBuffer> packer(sbuf);
    if (header >= 0) {
      packer.pack_int8(header);
    }

    if (x.IsArray()) {
      auto xsp = x.AsSpan<T>();
      packer.pack_array(xsp.length());  // pack meta: array length
      for (size_t i = 0; i < xsp.length(); ++i) {
        // pack meta: pack current element size
        packer.pack_str(this_ptr->Serialize(xsp[i], nullptr, 0));
        auto body_sz = this_ptr->Serialize(
            xsp[i], reinterpret_cast<uint8_t*>(sbuf.PosLoc()), sbuf.FreeSize());
        sbuf.IncPos(body_sz);
      }
      return sbuf.WrittenSize();
    } else {
      // single element case
      auto& xt = x.As<T>();
      auto sz = this_ptr->Serialize(xt, nullptr, 0);
      packer.pack_str(sz); /* pack header and size*/
      auto body_sz = this_ptr->Serialize(
          xt, reinterpret_cast<uint8_t*>(sbuf.PosLoc()), sbuf.FreeSize());
      return sbuf.WrittenSize() + body_sz;
    }
  }
};

}  // namespace yacl
