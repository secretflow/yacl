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

#include <memory>

#include "yacl/io/rw/schema.h"
#include "yacl/io/stream/interface.h"

namespace yacl::io {

struct ReaderOptions {
  // select feature to read
  Schema file_schema;
  // how many rows in one batch.
  size_t batch_size = 2000;
  // if read by column
  bool column_reader = false;
  // if next return data's col order following file's header
  // OR file_schema's order.
  bool use_header_order = false;
  // row reader count lines during Init().
  // this option is heavy.
  // keep this false if you do not need to get file lines before first full scan.
  bool row_reader_count_lines = false;
};

// NOT thread safe. see Spawn().
class Reader {
 public:
  virtual ~Reader() = default;

  virtual void Init() = 0;

  /**
   * return header, if exist. otherwise return empty vector.
   */
  virtual const std::vector<std::string>& Headers() const = 0;

  /**
   * Read the next row batch from the current position.
   * If column_reader == false, return next row batch.
   * If column_reader == true, return next column (only one col) & ignore
   * batch_size setting
   *
   * return:
   *     True, *data contains some data
   *     False, reach EOF & *data has no data.
   *
   * raise exception if any error happend.
   */
  virtual bool Next(ColumnVectorBatch* data) = 0;

  /**
   * Same as Next(data) above, BUT, size the second parameter will overide
   * global batch_size setting.
   *
   * And Col reader can get more than one col by this.
   *
   * return:
   *     True, *data contains some data
   *     False, reach EOF & *data has no data.
   *
   * raise exception if any error happend.
   */
  virtual bool Next(size_t size, ColumnVectorBatch* data) = 0;

  /**
   * If column_reader == false, return rows from begin.
   * If column_reader == true, return column index.
   */
  virtual size_t Tell() const = 0;

  /**
   * Sets input position by (column_reader == false ? ROW : COL)
   * index start from 0.
   * raise exception if out of range.
   */
  virtual void Seek(size_t index) = 0;

  /**
   * return total rows from input.
   *
   * if read by ROW and row_reader_count_lines == false,
   * return size_t(-1) before first full scan.
   *
   * if read by COL, always return real rows.
   */
  virtual size_t Rows() const = 0;

  /**
   * return total cols from input.
   */
  virtual size_t Cols() const = 0;

  /**
   * return total file size.
   */
  virtual size_t GetLength() const = 0;
  /**
   * If column_reader == false, return raw io current bytes from begin.
   * If column_reader == true, throw yacl::EnforceNotMet.
   */
  virtual size_t Tellg() = 0;

  /**
   * Reader is not thread safe.
   * Spawn another instance to read in new thread.
   * Spawn() is not thread safe too. DO NOT call Spawn() parallel.
   */
  virtual std::unique_ptr<Reader> Spawn() = 0;
};

}  // namespace yacl::io