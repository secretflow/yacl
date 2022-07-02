#include "yasl/io/rw/mmapped_file.h"

#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

#include <cstdio>
#include <filesystem>

#include "absl/base/internal/direct_mmap.h"
#include "absl/cleanup/cleanup.h"

#include "yasl/base/exception.h"

namespace yasl::io {

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

  YASL_ENFORCE(fd != -1, "failed to open file {}", path);

  // mmap whole file into memory
  data_ = absl::base_internal::DirectMmap(nullptr, size_, PROT_READ,
                                          MAP_PRIVATE, fd, 0);

  // Make sure mmap succeeded
  YASL_ENFORCE(data_ != MAP_FAILED, "mmap failed");
}

MmappedFile::~MmappedFile() {
  if (data_ != nullptr) {
    absl::base_internal::DirectMunmap(data_, size_);
  }
}

}  // namespace yasl::io
