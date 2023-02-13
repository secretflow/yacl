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

#include "yacl/io/stream/mem_io.h"

#include <fstream>
#include <string>
#include <utility>

namespace yacl::io {

MemInputStream::MemInputStream(const std::string& input_data)
    : input_data_(input_data), total_len_(input_data.size()) {
  input_data_.exceptions(std::ifstream::badbit);
}

bool MemInputStream::operator!() const {
  return !static_cast<bool>(input_data_);
}

MemInputStream::operator bool() const { return static_cast<bool>(input_data_); }

bool MemInputStream::Eof() const { return input_data_.eof(); }

InputStream& MemInputStream::GetLine(std::string* ret, char delim) {
  std::getline(input_data_, *ret, delim);
  return *this;
}

InputStream& MemInputStream::Read(void* buf, size_t length) {
  input_data_.readsome(static_cast<char*>(buf), length);
  return *this;
}

InputStream& MemInputStream::Seekg(size_t pos) {
  // clear EOF/FAIL bit
  input_data_.clear();
  input_data_.seekg(pos);
  return *this;
}

size_t MemInputStream::Tellg() {
  auto backup = input_data_.rdstate();
  input_data_.clear();
  // tellg fail if eofbit is set.
  auto ret = input_data_.tellg();
  input_data_.setstate(backup);
  return ret;
}

size_t MemInputStream::GetLength() const { return total_len_; }

const std::string& MemInputStream::GetName() const {
  static const std::string mem_io_name("MemInputStream");
  return mem_io_name;
}

void MemInputStream::Close() {
  input_data_.str(std::string());
  total_len_ = 0;
}

void MemOutputStream::Write(const void* buf, size_t length) {
  out_buffer_ << std::string(static_cast<const char*>(buf), length);
}

void MemOutputStream::Write(std::string_view buf) { out_buffer_ << buf; }

const std::string& MemOutputStream::GetName() const {
  static const std::string mem_io_name("MemOutputStream");
  return mem_io_name;
}

size_t MemOutputStream::Tellp() { return out_buffer_.tellp(); }

void MemOutputStream::Flush() {
  if (out_ != nullptr) {
    *out_ = out_buffer_.str();
  }
}

void MemOutputStream::Close() {
  if (out_ != nullptr) {
    *out_ = out_buffer_.str();
    out_buffer_.str(std::string());
    out_ = nullptr;
  }
}

std::unique_ptr<InputStream> MemInputStream::Spawn() {
  std::unique_ptr<InputStream> ret(new MemInputStream(input_data_.str()));
  ret->Seekg(Tellg());
  return ret;
}

}  // namespace yacl::io