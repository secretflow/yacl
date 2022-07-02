#include "yasl/base/buffer.h"

namespace yasl {

std::shared_ptr<Buffer> makeBuffer(int64_t size) {
  return std::make_shared<Buffer>(size);
}

std::shared_ptr<Buffer> makeBuffer(void const* ptr, int64_t size) {
  return std::make_shared<Buffer>(ptr, size);
}

std::shared_ptr<Buffer> makeBuffer(Buffer&& buf) {
  return std::make_shared<Buffer>(std::move(buf));
}

std::ostream& operator<<(std::ostream& out, const Buffer& v) {
  out << fmt::format("Buffer<{},{}>", v.data(), v.size());
  return out;
}

}  // namespace yasl
