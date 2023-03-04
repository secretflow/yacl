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

#include "yacl/io/rw/csv_reader.h"

#include <unistd.h>

#include <algorithm>
#include <filesystem>
#include <iterator>
#include <optional>
#include <random>
#include <string>
#include <utility>

#include "absl/strings/ascii.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_split.h"
#include "fmt/format.h"

#include "yacl/base/exception.h"
#include "yacl/io/rw/float.h"
#include "yacl/io/rw/mmapped_file.h"
#include "yacl/io/stream/file_io.h"

namespace yacl::io {

static const size_t kUnknowTotalRow = size_t(-1);

CsvReader::CsvReader(ReaderOptions options, std::unique_ptr<InputStream> in,
                     char field_delimiter, char line_delimiter)
    : options_(std::move(options)),
      field_delimiter_(field_delimiter),
      line_delimiter_(line_delimiter),
      inited_(false),
      in_(std::move(in)),
      current_index_(0),
      total_rows_(kUnknowTotalRow) {}

CsvReader::MmapDirGuard::~MmapDirGuard() {
  if (!dir_.empty()) {
    try {
      // try remove.
      std::filesystem::remove_all(dir_);
    } catch (const std::exception&) {
      // if error. do nothing.
    }
  }
}

void CsvReader::Init() {
  YACL_ENFORCE(!inited_, "DO NOT call init multiply times");

  ParseHeader();

  const auto& schema = options_.file_schema;
  YACL_ENFORCE(schema.feature_names.size() == schema.feature_types.size());
  const size_t f_size = schema.feature_names.size();
  // col reader do not support empty feature.
  YACL_ENFORCE(options_.column_reader == false || f_size > 0);

  selected_features_.reserve(f_size);
  for (size_t i = 0; i < f_size; i++) {
    const auto& f_name = schema.feature_names[i];
    auto it = std::find(headers_.begin(), headers_.end(), f_name);
    if (it == headers_.end()) {
      YACL_THROW_ARGUMENT_ERROR(
          "Input CSV read options error: "
          "can't find feature names '{}' in file '{}'",
          f_name, in_->GetName());
    }

    size_t idx = std::distance(headers_.begin(), it);
    selected_features_.emplace_back(idx, schema.feature_types[i]);
  }

  if (options_.use_header_order) {
    std::sort(selected_features_.begin(), selected_features_.end(),
              [](auto& a, auto& b) { return a.first < b.first; });
  }

  if (options_.column_reader) {
    // split features into mmap files.
    BuildMmapFiles();
  } else {
    // init rows_map_, in_->Tell() is the point to ROW 0's start position.
    UpdateRowMap();
    if (options_.row_reader_count_lines) {
      CountLines();
    }
  }
  inited_ = true;
  Seek(0);
}

void CsvReader::CountLines() {
  while (in_->GetLine(&current_line_, line_delimiter_)) {
    current_index_++;
    if (current_index_ % options_.batch_size == 0) {
      UpdateRowMap();
    }
  }
  total_rows_ = current_index_;
}

bool CsvReader::NextLine(std::vector<absl::string_view>* fields) {
  if (!in_->GetLine(&current_line_, line_delimiter_)) {
    return false;
  }
  if (fields != nullptr) {
    *fields = absl::StrSplit(current_line_, field_delimiter_);
  }
  return true;
}

void CsvReader::ParseHeader() {
  std::vector<absl::string_view> headers;
  YACL_ENFORCE(NextLine(&headers), "Can't get header from file '{}'",
               in_->GetName());
  headers_.reserve(headers.size());
  for (auto& h : headers) {
    auto striped_h = static_cast<std::string>(absl::StripAsciiWhitespace(h));
    if (striped_h.empty()) {
      YACL_THROW_INVALID_FORMAT(
          "Input CSV file format error: "
          "found empty field name in headers from file '{}'",
          in_->GetName());
    }

    auto it = std::find(headers_.begin(), headers_.end(), striped_h);
    if (it != headers_.end()) {
      YACL_THROW_INVALID_FORMAT(
          "Input CSV file format error: "
          "Repeated fields found in header from file '{}'",
          in_->GetName());
    }

    headers_.push_back(striped_h);
  }
}

void CsvReader::UpdateRowMap() {
  auto it = rows_map_.upper_bound(current_index_);
  if (it != rows_map_.end()) {
    return;
  }
  YACL_ENFORCE(!options_.column_reader);
  rows_map_.insert({current_index_, in_->Tellg()});
}

void CsvReader::BuildMmapFiles() {
  std::vector<absl::string_view> fields;
  std::vector<std::unique_ptr<OutputStream>> oss;
  oss.reserve(selected_features_.size());
  cols_mmap_file_.reserve(selected_features_.size());
  // make sure mmap_dir_ is non-repeating in work path.
  mmap_dir_ = std::make_shared<MmapDirGuard>(fmt::format(
      "mmap.{}.{}.{}", getpid(), fmt::ptr(this), std::random_device()()));
  for (size_t i = 0; i < selected_features_.size(); i++) {
    // mmap.{pid}.{reader}/f{feat indxe}.mmap
    std::string mmap_name = fmt::format("{}/f{}.mmap", mmap_dir_->Dir(), i);
    cols_mmap_file_.push_back(mmap_name);
    oss.emplace_back(new FileOutputStream(mmap_name));
  }
  size_t row_count = 0;
  while (NextLine(&fields)) {
    if (fields.size() != headers_.size()) {
      YACL_THROW_INVALID_FORMAT(
          "Input CSV file format error: "
          "Line#{} fields size '{}' != header's size '{}'",
          row_count, fields.size(), headers_.size());
    }

    row_count++;
    for (size_t i = 0; i < selected_features_.size(); i++) {
      auto index = selected_features_[i].first;
      auto type = selected_features_[i].second;
      auto& field = fields[index];
      switch (type) {
        case Schema::STRING: {
          // STRING mmap format:
          /*
          ┌────┬───────────┬────┬───────────┐
          │Len │Str Value  │Len │Str Value  │...
          └────┴───────────┴────┴───────────┘
          */
          uint32_t len = field.size();
          const char* data = field.data();
          oss[i]->Write(reinterpret_cast<char*>(&len), sizeof(uint32_t));
          oss[i]->Write(data, len);
          break;
        }
        case Schema::FLOAT: {
          // FLOAT mmap format:
          // │ FLOAT │ FLOAT │ ...
          float value = 0;
          if (!FloatFromString(field, &value)) {
            YACL_THROW_INVALID_FORMAT(
                "Input CSV file format error: Cannot convert '{}' to "
                "float, column '{}', {}, file '{}'",
                std::string(field), headers_[index], current_index_,
                in_->GetName());
          }
          oss[i]->Write(reinterpret_cast<char*>(&value), sizeof(float));
          break;
        }
        case Schema::DOUBLE: {
          // DOUBLE mmap format:
          // │ DOUBLE │ DOUBLE │ ...
          double value = 0;
          if (!FloatFromString(field, &value)) {
            YACL_THROW_INVALID_FORMAT(
                "Input CSV file format error: Cannot convert '{}' to "
                "double, column '{}', {}, file '{}'",
                std::string(field), headers_[index], current_index_,
                in_->GetName());
          }

          oss[i]->Write(reinterpret_cast<char*>(&value), sizeof(double));
          break;
        }
        default:
          YACL_THROW("unknow Schema::type {}", type);
      }
    }
  }
  total_rows_ = row_count;
  {
    // close all oss before auto release.
    std::optional<yacl::Exception> ope;
    for (auto& os : oss) {
      try {
        os->Close();
      } catch (const yacl::Exception& e) {
        ope = e;
      }
    }
    // if any error happend, rethrow it.
    if (ope) {
      throw ope.value();
    }
  }
}

bool CsvReader::Next(ColumnVectorBatch* data) {
  YACL_ENFORCE(inited_, "Please Call Init before use reader");
  data->Clear();
  if (options_.column_reader) {
    return NextCol(data);
  } else {
    return NextRow(data, options_.batch_size);
  }
}

bool CsvReader::Next(size_t size, ColumnVectorBatch* data) {
  YACL_ENFORCE(size != 0);
  YACL_ENFORCE(inited_, "Please Call Init before use reader");
  data->Clear();
  if (options_.column_reader) {
    size_t count = 0;
    while (count < size) {
      if (!NextCol(data)) {
        break;
      }
      count++;
    }
    return count != 0;
  } else {
    return NextRow(data, size);
  }
}

bool CsvReader::NextCol(ColumnVectorBatch* data) {
  YACL_ENFORCE(total_rows_ != kUnknowTotalRow);
  if (current_index_ == selected_features_.size()) {
    return false;
  }
  auto col_index = current_index_++;
  auto type = selected_features_[col_index].second;

  MmappedFile mmap_col(cols_mmap_file_[col_index]);
  const char* mmap_data = mmap_col.data();
  const size_t mmap_size = mmap_col.size();

  switch (type) {
    case Schema::STRING: {
      StringColumnVector col;
      col.reserve(total_rows_);

      size_t pos = 0;
      while (pos < mmap_size) {
        YACL_ENFORCE(pos + sizeof(uint32_t) <= mmap_size);
        uint32_t len;
        std::memcpy(&len, mmap_data + pos, sizeof(uint32_t));
        pos += sizeof(uint32_t);

        YACL_ENFORCE(pos + len <= mmap_size);
        const char* str = mmap_data + pos;
        pos += len;

        col.emplace_back(str, len);
      }
      YACL_ENFORCE(col.size() == total_rows_);
      data->AppendCol(std::move(col));
      break;
    }
    case Schema::FLOAT: {
      FloatColumnVector col;
      col.reserve(total_rows_);
      YACL_ENFORCE(mmap_size == total_rows_ * sizeof(float));

      size_t pos = 0;
      while (pos < mmap_size) {
        float value = *reinterpret_cast<const float*>(mmap_data + pos);
        col.push_back(value);
        pos += sizeof(float);
      }
      YACL_ENFORCE(col.size() == total_rows_);
      data->AppendCol(std::move(col));
      break;
    }
    case Schema::DOUBLE: {
      DoubleColumnVector col;
      col.reserve(total_rows_);
      YACL_ENFORCE(mmap_size == total_rows_ * sizeof(double));

      size_t pos = 0;
      while (pos < mmap_size) {
        double value = *reinterpret_cast<const double*>(mmap_data + pos);
        col.push_back(value);
        pos += sizeof(double);
      }
      YACL_ENFORCE(col.size() == total_rows_);
      data->AppendCol(std::move(col));
      break;
    }
    default:
      YACL_THROW("unknow Schema::type {}", type);
  }

  return true;
}

void CsvReader::InitBatchCols(std::vector<ColumnType>* cols,
                              size_t batch_size) {
  cols->reserve(selected_features_.size());
  for (auto& selected_feature : selected_features_) {
    auto type = selected_feature.second;
    switch (type) {
      case Schema::STRING: {
        StringColumnVector col;
        col.reserve(batch_size);
        cols->emplace_back(std::move(col));
        break;
      }
      case Schema::FLOAT: {
        FloatColumnVector col;
        col.reserve(batch_size);
        cols->emplace_back(std::move(col));
        break;
      }
      case Schema::DOUBLE: {
        DoubleColumnVector col;
        col.reserve(batch_size);
        cols->emplace_back(std::move(col));
        break;
      }
      default:
        YACL_THROW("unknow Schema::type {}", type);
    }
  }
}

bool CsvReader::NextRow(ColumnVectorBatch* data, size_t batch_size) {
  if (in_->Eof()) {
    // EOF
    return false;
  }

  std::vector<ColumnType> cols;
  InitBatchCols(&cols, batch_size);

  size_t count = 0;
  std::vector<absl::string_view> fields;
  while (count < batch_size && NextLine(&fields)) {
    if (fields.size() != headers_.size()) {
      YACL_THROW_INVALID_FORMAT(
          "Input CSV file format error: "
          "Line#{} fields size '{}' != header's size '{}'",
          current_index_, fields.size(), headers_.size());
    }

    count++;
    current_index_++;

    for (size_t i = 0; i < selected_features_.size(); i++) {
      auto index = selected_features_[i].first;
      auto type = selected_features_[i].second;
      auto& field = fields[index];
      switch (type) {
        case Schema::STRING: {
          auto& col = std::get<StringColumnVector>(cols.at(i));
          col.emplace_back(field.data(), field.size());
          break;
        }
        case Schema::FLOAT: {
          float value = 0;
          if (!FloatFromString(field, &value)) {
            YACL_THROW_INVALID_FORMAT(
                "Input CSV file format error: Cannot convert '{}' to "
                "float, column '{}', {}, file '{}'",
                std::string(field), headers_[index], current_index_,
                in_->GetName());
          }

          auto& col = std::get<FloatColumnVector>(cols.at(i));
          col.push_back(value);
          break;
        }
        case Schema::DOUBLE: {
          double value = 0;
          if (!FloatFromString(field, &value)) {
            YACL_THROW_INVALID_FORMAT(
                "Input CSV file format error: Cannot convert '{}' to "
                "double, column '{}', {}, file '{}'",
                std::string(field), headers_[index], current_index_,
                in_->GetName());
          }

          auto& col = std::get<DoubleColumnVector>(cols.at(i));
          col.push_back(value);
          break;
        }
        default:
          YACL_THROW("unknow Schema::type {}", type);
      }
    }
  }

  if (count == batch_size) {
    // for fast seek
    UpdateRowMap();
  }
  if (in_->Eof()) {
    // scan over, save rows.
    total_rows_ = current_index_;
  }

  if (!selected_features_.empty()) {
    data->Reserve(selected_features_.size());
    for (auto& c : cols) {
      data->AppendCol(std::move(c));
    }
  } else {
    *data = ColumnVectorBatch::EmptyBatch(count);
  }

  return count != 0;
}

void CsvReader::Seek(size_t index) {
  YACL_ENFORCE(inited_, "Please Call Init before use reader");
  if (options_.column_reader) {
    YACL_ENFORCE(index < selected_features_.size(),
                 "seek for col out of range, try {} max {}", index,
                 selected_features_.size());
    current_index_ = index;
  } else {
    YACL_ENFORCE(total_rows_ == kUnknowTotalRow || index < total_rows_,
                 "seek for row out of range, try {} max {}", index,
                 total_rows_);
    auto it = rows_map_.upper_bound(index);
    YACL_ENFORCE(it != rows_map_.begin());
    std::advance(it, -1);
    in_->Seekg(it->second);
    current_index_ = it->first;
    while (current_index_ < index && NextLine(nullptr)) {
      current_index_++;
    }
    YACL_ENFORCE(current_index_ == index,
                 "seek for row out of range, try {} max {}", index,
                 current_index_);
  }
}

std::unique_ptr<Reader> CsvReader::Spawn() {
  YACL_ENFORCE(inited_, "CAN NOT Spawn before init");
  auto in = in_->Spawn();
  YACL_ENFORCE(in_->Tellg() == in->Tellg());
  std::unique_ptr<CsvReader> ret(new CsvReader(
      options_, std::move(in), field_delimiter_, line_delimiter_));
  ret->inited_ = true;
  ret->headers_ = headers_;
  ret->selected_features_ = selected_features_;
  ret->current_index_ = current_index_;
  ret->total_rows_ = total_rows_;
  ret->rows_map_ = rows_map_;
  ret->cols_mmap_file_ = cols_mmap_file_;
  // use shared_ptr as dir ref counter.
  ret->mmap_dir_ = mmap_dir_;
  return ret;
}

}  // namespace yacl::io