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

#include <cstddef>
#include <memory>
#include <string>
#include <string_view>

namespace yacl::io {

// NOT thread safe.  see Spawn().
class InputStream {
 public:
  virtual ~InputStream() = default;
  /**
   * return True if EOF.
   */
  virtual bool operator!() const = 0;

  /**
   * return True if not EOF.
   */
  virtual explicit operator bool() const = 0;

  virtual bool Eof() const = 0;

  /**
   * read line from file.
   * raise exception if any error happened except EOF.
   */
  virtual InputStream& GetLine(std::string* ret, char delim) = 0;
  virtual InputStream& GetLine(std::string* ret) { return GetLine(ret, '\n'); }

  /**
   * Read length bytes from the file.
   * raise exception if any error happened except EOF.
   */
  virtual InputStream& Read(void* buf, size_t length) = 0;

  /**
   * Sets input position.
   * raise exception if any error happened.
   */
  virtual InputStream& Seekg(size_t pos) = 0;

  /**
   * Sets input position.
   * raise exception if any error happened.
   */
  virtual size_t Tellg() = 0;

  /**
   * Get the total length of the file in bytes.
   */
  virtual size_t GetLength() const = 0;

  /**
   * Get the name of the stream for error messages.
   */
  virtual const std::string& GetName() const = 0;

  /**
   * Close the stream and free all buffer.
   */
  virtual void Close() = 0;

  // false for block device like local files;
  // true for network streaming like stream from oss.
  virtual bool IsStreaming() = 0;

  /**
   * InputStream is not thread safe.
   * Spawn another instance to read in new thread.
   * Copy all inter state from *this.
   * Spawn() is not thread safe too. DO NOT call Spawn() parallel.
   */
  virtual std::unique_ptr<InputStream> Spawn() = 0;
};

/**
 * Always trunc file if target file exists.
 */
class OutputStream {
 public:
  virtual ~OutputStream() = default;

  /**
   * Write/Append length bytes pointed by buf to the file stream
   * raise exception if any error happened.
   */
  virtual void Write(const void* buf, size_t length) = 0;
  virtual void Write(std::string_view buf) = 0;

  /**
   * Get the name of the stream for error messages.
   */
  virtual const std::string& GetName() const = 0;

  /**
   * returns the output position indicator
   */
  virtual size_t Tellp() = 0;

  // append only fs like oss / hdfs do not support seek.

  virtual void Flush() = 0;
  /**
   * Close the stream and flush any pending data
   */
  virtual void Close() = 0;

  // false for block device like local files;
  // true for network streaming like stream from oss.
  virtual bool IsStreaming() = 0;
};

}  // namespace yacl::io