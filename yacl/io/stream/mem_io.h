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

#include <sstream>

#include "yacl/io/stream/interface.h"

namespace yacl::io {

class MemInputStream : public InputStream {
 public:
  explicit MemInputStream(const std::string& input_data);

  ~MemInputStream() override = default;

  bool operator!() const override;

  explicit operator bool() const override;

  bool Eof() const override;

  InputStream& GetLine(std::string* ret, char delim) override;

  InputStream& Read(void* buf, size_t length) override;

  InputStream& Seekg(size_t pos) override;

  size_t Tellg() override;

  size_t GetLength() const override;

  const std::string& GetName() const override;

  void Close() override;

  bool IsStreaming() override { return false; }

  std::unique_ptr<InputStream> Spawn() override;

 private:
  std::istringstream input_data_;
  size_t total_len_;
};

class MemOutputStream : public OutputStream {
 public:
  explicit MemOutputStream(std::string* out) : out_(out) {}

  ~MemOutputStream() override { Close(); }

  /**
   * Write/Append length bytes pointed by buf to the file stream
   * raise exception if any error happend.
   */
  void Write(const void* buf, size_t length) override;
  void Write(std::string_view buf) override;

  /**
   * Get the name of the stream for error messages.
   */
  const std::string& GetName() const override;

  /**
   * returns the output position indicator
   */
  size_t Tellp() override;

  // append only fs like oss / hdfs do not support seek.

  /**
   * Close the stream and flush any pending data
   */
  void Close() override;

  void Flush() override;

  // false for block device like local files;
  // true for network streaming like stream from oss.
  bool IsStreaming() override { return false; }

 private:
  std::ostringstream out_buffer_;
  std::string* out_;
};

}  // namespace yacl::io
