#pragma once

#include <cstdint>
#include <string>

namespace yasl::io {

class MmappedFile {
 public:
  explicit MmappedFile(const std::string &path);
  ~MmappedFile();

  const char *data() const { return static_cast<const char *>(data_); }

  size_t size() const { return size_; };

 private:
  void *data_{nullptr};
  std::uintmax_t size_{0};
};

}  // namespace yasl::io
