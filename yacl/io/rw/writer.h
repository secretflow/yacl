// Copyright 2019 Ant Group Co., Ltd.
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
#include <limits>

#include "yacl/io/rw/schema.h"
#include "yacl/io/stream/interface.h"

namespace yacl::io {

struct WriterOptions {
  // file format
  Schema file_schema;
  // precision for format float.
  // assert( float_precision <= max_digits10 )
  int float_precision = std::numeric_limits<float>::max_digits10;
};

// NOT thread safe and append only.
// !!! PLS Call Close before release Writer !!!
class Writer {
 public:
  virtual ~Writer() = default;

  virtual void Init() = 0;

  /**
   * write batch into file. only support row batch & append only:
   * assert(data.size() == file_schema.size())
   * assert(data[0].size() == data[N].size())
   */
  virtual bool Add(const ColumnVectorBatch&) = 0;

  // flush padding data.
  virtual void Flush() = 0;
  // close all underlay resource.
  virtual void Close() = 0;

  // written size in bytes.
  virtual size_t Tellp() = 0;
};

}  // namespace yacl::io
