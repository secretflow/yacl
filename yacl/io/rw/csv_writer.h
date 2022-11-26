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
#include "yacl/io/rw/writer.h"

namespace yacl::io {

class CsvWriter : public Writer {
 public:
  CsvWriter(WriterOptions, std::unique_ptr<OutputStream>,
            char field_delimiter = ',', char line_delimiter = '\n');

  ~CsvWriter() override = default;

  void Init() override;

  bool Add(const ColumnVectorBatch&) override;

  void Flush() override;

  void Close() override;

  size_t Tellp() override {
    YACL_ENFORCE(inited_, "Please Call Init before use writer");
    return out_->Tellp();
  }

 private:
  const WriterOptions options_;
  const std::string field_delimiter_;
  const std::string line_delimiter_;
  bool inited_;
  std::unique_ptr<OutputStream> out_;
};

}  // namespace yacl::io
