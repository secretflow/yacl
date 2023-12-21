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

#include "yacl/io/msgpack/spec_traits.h"

namespace yacl::io::msgpack_traits {

size_t HeadSizeOfStr(size_t str_len) {
  // Str format family stores a byte array in 1, 2, 3, or 5 bytes of extra bytes
  // in addition to the size of the byte array.
  if (str_len < 32) {
    // fixstr stores a byte array whose length is upto 31 bytes:
    // +--------+========+
    // |101XXXXX|  data  |
    // +--------+========+
    return 1;

  } else if (str_len < 256) {
    // str 8 stores a byte array whose length is upto (2^8)-1 bytes:
    // +--------+--------+========+
    // |  0xd9  |YYYYYYYY|  data  |
    // +--------+--------+========+
    return 2;

  } else if (str_len < 65536) {
    // str 16 stores a byte array whose length is upto (2^16)-1 bytes:
    // +--------+--------+--------+========+
    // |  0xda  |ZZZZZZZZ|ZZZZZZZZ|  data  |
    // +--------+--------+--------+========+
    return 3;

  } else {
    // str 32 stores a byte array whose length is upto (2^32)-1 bytes:
    // +--------+--------+--------+--------+--------+========+
    // |  0xdb  |AAAAAAAA|AAAAAAAA|AAAAAAAA|AAAAAAAA|  data  |
    // +--------+--------+--------+--------+--------+========+
    return 5;
  }
}

size_t HeadSizeOfArray(size_t array_len) {
  // Array format family stores a sequence of elements in 1, 3, or 5 bytes of
  // extra bytes in addition to the elements.
  if (array_len < 16) {
    // fixarray stores an array whose length is upto 15 elements:
    // +--------+~~~~~~~~~~~~~~~~~+
    // |1001XXXX|    N objects    |
    // +--------+~~~~~~~~~~~~~~~~~+
    return 1;

  } else if (array_len < 65536) {
    // array 16 stores an array whose length is upto (2^16)-1 elements:
    // +--------+--------+--------+~~~~~~~~~~~~~~~~~+
    // |  0xdc  |YYYYYYYY|YYYYYYYY|    N objects    |
    // +--------+--------+--------+~~~~~~~~~~~~~~~~~+
    return 3;

  } else {
    // array 32 stores an array whose length is upto (2^32)-1 elements:
    // +--------+--------+--------+--------+--------+~~~~~~~~~~~~~~~~~+
    // |  0xdd  |ZZZZZZZZ|ZZZZZZZZ|ZZZZZZZZ|ZZZZZZZZ|    N objects    |
    // +--------+--------+--------+--------+--------+~~~~~~~~~~~~~~~~~+
    return 5;
  }
}

}  // namespace yacl::io::msgpack_traits
