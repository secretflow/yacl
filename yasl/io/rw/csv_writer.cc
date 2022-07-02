#include "yasl/io/rw/csv_writer.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <filesystem>
#include <iterator>
#include <string>
#include <utility>

#include "fmt/format.h"

#include "yasl/base/exception.h"
#include "yasl/io/rw/float.h"

namespace yasl::io {

CsvWriter::CsvWriter(WriterOptions op, std::unique_ptr<OutputStream> out,
                     char field_delimiter, char line_delimiter)
    : options_(std::move(op)),
      field_delimiter_(1, field_delimiter),
      line_delimiter_(1, line_delimiter),
      inited_(false),
      out_(std::move(out)) {
  YASL_ENFORCE(!options_.file_schema.feature_names.empty());
  YASL_ENFORCE(options_.file_schema.feature_names.size() ==
               options_.file_schema.feature_types.size());
  YASL_ENFORCE(out_->Tellp() == 0);
  YASL_ENFORCE(options_.float_precision > 0 &&
               options_.float_precision <=
                   std::numeric_limits<double>::max_digits10);
}

void CsvWriter::Flush() { out_->Flush(); }

void CsvWriter::Close() { out_->Close(); }

void CsvWriter::Init() {
  YASL_ENFORCE(!inited_, "DO NOT call init multiply times");
  // write header.
  const auto& fn = options_.file_schema.feature_names;
  auto header_line =
      fmt::format("{}", fmt::join(fn.begin(), fn.end(), field_delimiter_));
  out_->Write(header_line.c_str(), header_line.size());
  out_->Write(line_delimiter_.c_str(), line_delimiter_.size());
  inited_ = true;
}

bool CsvWriter::Add(const ColumnVectorBatch& data) {
  YASL_ENFORCE(inited_, "Please Call Init before use writer");
  const size_t rows = data.Shape().rows;
  const size_t cols = data.Shape().cols;
  YASL_ENFORCE(cols == options_.file_schema.feature_names.size());
  const auto& types = options_.file_schema.feature_types;

  for (size_t r = 0; r < rows; r++) {
    for (size_t c = 0; c < cols; c++) {
      switch (types[c]) {
        case Schema::FLOAT: {
          auto v =
              FloatToString(data.At<float>(r, c), options_.float_precision);
          out_->Write(v.c_str(), v.size());
          break;
        }
        case Schema::DOUBLE: {
          auto v =
              FloatToString(data.At<double>(r, c), options_.float_precision);
          out_->Write(v.c_str(), v.size());
          break;
        }
        case Schema::STRING: {
          const auto& v = data.At<std::string>(r, c);
          out_->Write(v.c_str(), v.size());
          break;
        }
        default:
          YASL_THROW("unknow Schema::type {}", types[c]);
      }
      if (c + 1 != cols) {
        out_->Write(field_delimiter_.c_str(), field_delimiter_.size());
      }
    }
    out_->Write(line_delimiter_.c_str(), line_delimiter_.size());
  }
  return true;
}

}  // namespace yasl::io