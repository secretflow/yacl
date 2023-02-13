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

#include "yacl/io/stream/file_io.h"

#include <cerrno>
#include <cstring>
#include <exception>
#include <filesystem>
#include <iostream>
#include <string>
#include <utility>

#include "fmt/format.h"
#include "spdlog/spdlog.h"

#include "yacl/base/exception.h"

namespace yacl::io {

#define FILE_IO_THROW(msg_prefix)                                         \
  YACL_THROW_IO_ERROR(                                                    \
      msg_prefix                                                          \
      " error on file '{}', failure '{}', error msg '{}', error code {}", \
      file_name_, e.what(), std::strerror(errno), errno);

FileInputStream::FileInputStream(std::string file_name)
    : file_name_(std::move(file_name)), file_len_(0) {
#ifndef __arm64__
  in_.exceptions(std::ifstream::badbit | std::ifstream::failbit);
#endif
  try {
    in_.open(file_name_, std::ios::binary | std::ios::ate);
  } catch (const std::ifstream::failure& e) {
    FILE_IO_THROW("Open for read");
  }
  file_len_ = Tellg();
  Seekg(0);
}

bool FileInputStream::operator!() const { return !static_cast<bool>(in_); }

FileInputStream::operator bool() const { return static_cast<bool>(in_); }

bool FileInputStream::Eof() const { return in_.eof(); }

InputStream& FileInputStream::GetLine(std::string* ret, char delim) {
  try {
    std::getline(in_, *ret, delim);
  } catch (const std::ifstream::failure& e) {
    if (!in_.eof() || in_.bad()) {
      FILE_IO_THROW("GetLine");
    }
  }

  return *this;
}

InputStream& FileInputStream::Read(void* buf, size_t length) {
  try {
    in_.read(static_cast<char*>(buf), length);
  } catch (const std::ifstream::failure& e) {
    FILE_IO_THROW("Read");
  }
  return *this;
}

InputStream& FileInputStream::Seekg(size_t pos) {
  try {
    // clear EOF/FAIL bit
    in_.clear();
    in_.seekg(pos);
  } catch (const std::ifstream::failure& e) {
    FILE_IO_THROW("Seekg");
  }
  return *this;
}

size_t FileInputStream::Tellg() {
  size_t ret = 0;
  try {
    auto backup = in_.rdstate();
    in_.clear();
    // tellg fail if eofbit is set.
    ret = in_.tellg();
    in_.clear(backup);
  } catch (const std::ifstream::failure& e) {
    if (in_.bad()) {
      FILE_IO_THROW("Tellg");
    }
  }
  return ret;
}

size_t FileInputStream::GetLength() const { return file_len_; }

const std::string& FileInputStream::GetName() const { return file_name_; }

void FileInputStream::Close() {
  try {
    in_.close();
  } catch (const std::ifstream::failure& e) {
    FILE_IO_THROW("Close");
  }
  file_len_ = 0;
}

std::unique_ptr<InputStream> FileInputStream::Spawn() {
  std::unique_ptr<InputStream> ret(new FileInputStream(file_name_));
  ret->Seekg(Tellg());
  return ret;
}

FileOutputStream::FileOutputStream(std::string file_name, bool trunc,
                                   bool exit_fail_in_destructor)
    : file_name_(std::move(file_name)),
      exit_fail_in_destructor_(exit_fail_in_destructor) {
  std::filesystem::path fp(file_name_);
  // empty if relative path to pwd.
  if (!fp.parent_path().empty() && !std::filesystem::exists(fp.parent_path())) {
    YACL_ENFORCE(std::filesystem::create_directories(fp.parent_path()),
                 "Failed to create dir ({})", fp.parent_path().string());
  }
  out_.exceptions(std::ofstream::badbit | std::ofstream::failbit);
  try {
    out_.open(file_name_,
              std::ios::binary | (trunc ? std::ios::trunc : std::ios::app));
  } catch (const std::ofstream::failure& e) {
    FILE_IO_THROW("Open for write");
  }
}

FileOutputStream::~FileOutputStream() {
  try {
    Close();
  } catch (const yacl::Exception& e) {
    SPDLOG_ERROR("IO error in destructor: < {} >\nStack:\n{}\n", e.what(),
                 e.stack_trace());
    if (exit_fail_in_destructor_) {
      _exit(-1);
    }
  } catch (const std::exception& e) {
    SPDLOG_ERROR("IO error in destructor: < {} >", e.what());
    if (exit_fail_in_destructor_) {
      _exit(-1);
    }
  }
}

void FileOutputStream::Write(const void* buf, size_t length) {
  try {
    out_.write(static_cast<const char*>(buf), length);
  } catch (const std::ofstream::failure& e) {
    FILE_IO_THROW("Write");
  }
}

void FileOutputStream::Write(std::string_view buf) {
  try {
    out_.write(buf.data(), buf.size());
  } catch (const std::ofstream::failure& e) {
    FILE_IO_THROW("Write");
  }
}

const std::string& FileOutputStream::GetName() const { return file_name_; }

size_t FileOutputStream::Tellp() {
  size_t ret = 0;
  try {
    ret = out_.tellp();
  } catch (const std::ofstream::failure& e) {
    FILE_IO_THROW("Tellp");
  }
  return ret;
}

void FileOutputStream::Flush() {
  try {
    if (out_.is_open() && out_.good()) {
      out_.flush();
    }
  } catch (const std::ofstream::failure& e) {
    FILE_IO_THROW("Flush");
  }
}

void FileOutputStream::Close() {
  try {
    if (out_.is_open() && out_.good()) {
      Flush();
      out_.close();
    }
  } catch (const std::ofstream::failure& e) {
    FILE_IO_THROW("Close");
  }
}

}  // namespace yacl::io
