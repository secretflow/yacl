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

#include "yacl/io/rw/mmapped_file.h"

#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

#include <cstdio>
#include <filesystem>

#include "absl/base/internal/direct_mmap.h"
#include "absl/cleanup/cleanup.h"

#include "yacl/base/exception.h"

namespace yacl::io {

MmappedFile::MmappedFile(const std::string &path) {
  // Get file size
  size_ = std::filesystem::file_size(path);

  // Open file
  auto fd = open(path.c_str(), O_RDONLY);
  absl::Cleanup close_fd = [&fd]() {
    // By posix standard, close the file will
    // not unmap the region, so let's close
    // the file.
    close(fd);
  };

  YACL_ENFORCE(fd != -1, "failed to open file {}", path);

  // mmap whole file into memory
  data_ = absl::base_internal::DirectMmap(nullptr, size_, PROT_READ,
                                          MAP_PRIVATE, fd, 0);

  // Make sure mmap succeeded
  YACL_ENFORCE(data_ != MAP_FAILED, "mmap failed");
}

MmappedFile::~MmappedFile() {
  if (data_ != nullptr) {
    absl::base_internal::DirectMunmap(data_, size_);
  }
}

}  // namespace yacl::io
