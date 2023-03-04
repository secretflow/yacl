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

#include <map>
#include <memory>
#include <utility>
#include <vector>

#include "absl/strings/string_view.h"

#include "yacl/io/rw/reader.h"

namespace yacl::io {

class CsvReader : public Reader {
 private:
  class MmapDirGuard {
   public:
    explicit MmapDirGuard(std::string dir) : dir_(std::move(dir)) {}
    ~MmapDirGuard();
    const std::string& Dir() const { return dir_; }

   private:
    const std::string dir_;
  };

 public:
  CsvReader(ReaderOptions options, std::unique_ptr<InputStream> in,
            char field_delimiter = ',', char line_delimiter = '\n');

  ~CsvReader() override = default;

  void Init() override;

  const std::vector<std::string>& Headers() const override {
    YACL_ENFORCE(inited_, "Please Call Init before use reader");
    return headers_;
  }

  /**
   * Read the next row batch from the current position.
   * If column_reader == false, return next row batch.
   * If column_reader == true, return next column & ignore batch_size.
   */
  bool Next(ColumnVectorBatch* data) override;

  /**
   * Same as Next(data) above, BUT, size the second parameter will override
   * global batch_size setting.
   *
   * And Col reader can get more than one col by this.
   */
  bool Next(size_t size, ColumnVectorBatch* data) override;

  /**
   * If column_reader == false, return rows from begin.
   * If column_reader == true, return column index.
   */
  size_t Tell() const override {
    YACL_ENFORCE(inited_, "Please Call Init before use reader");
    return current_index_;
  }

  /**
   * Sets input position by (column_reader == false ? ROW : COL)
   */
  void Seek(size_t index) override;

  size_t Rows() const override {
    YACL_ENFORCE(inited_, "Please Call Init before use reader");
    return total_rows_;
  }

  size_t Cols() const override {
    YACL_ENFORCE(inited_, "Please Call Init before use reader");
    return selected_features_.size();
  }

  std::unique_ptr<Reader> Spawn() override;

  size_t GetLength() const override {
    YACL_ENFORCE(inited_, "Please Call Init before use reader");
    return in_->GetLength();
  }

  size_t Tellg() override {
    YACL_ENFORCE(inited_, "Please Call Init before use reader");
    YACL_ENFORCE(!options_.column_reader, "Not callable if read by column");
    return in_->Tellg();
  }

 private:
  void CountLines();
  void ParseHeader();
  void UpdateRowMap();
  bool NextLine(std::vector<absl::string_view>*);

  void BuildMmapFiles();

  bool NextCol(ColumnVectorBatch*);
  bool NextRow(ColumnVectorBatch*, size_t);
  void InitBatchCols(std::vector<ColumnType>*, size_t);

  const ReaderOptions options_;
  const char field_delimiter_;
  const char line_delimiter_;
  bool inited_;
  std::unique_ptr<InputStream> in_;
  std::vector<std::string> headers_;
  // selected_features' index & type.
  std::vector<std::pair<size_t, Schema::Type>> selected_features_;
  std::string current_line_;
  // current row or col.
  size_t current_index_;
  // total. not available before full scan if use row reader.
  size_t total_rows_;
  // for ROW reader
  // rows -> file position.
  std::map<size_t, size_t> rows_map_;
  // for COL reader
  // index -> file name
  std::vector<std::string> cols_mmap_file_;
  std::shared_ptr<MmapDirGuard> mmap_dir_;
};

}  // namespace yacl::io
