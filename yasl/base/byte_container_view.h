#pragma once

#include <string>
#include <type_traits>

#include "absl/types/span.h"

#include "yasl/base/buffer.h"

namespace yasl {

// ByteContainerView is an extension to absl::Span that can take various
// containers that can store bytes (e.g., std::string, std::vector<uint8_t>,
// etc.) and use as a span.
class ByteContainerView : public absl::Span<const uint8_t> {
 public:
  using absl::Span<const uint8_t>::Span;

  template <typename T, std::enable_if_t<sizeof(T) == 1, bool> = true>
  /* implicit */ ByteContainerView(const T *v, size_t size)
      : Span(reinterpret_cast<const uint8_t *>(v), size) {}

  /* implicit */ ByteContainerView(const void *v, size_t size)
      : Span(static_cast<const uint8_t *>(v), size) {}

  template <typename ByteContainer,
            std::enable_if_t<sizeof(typename ByteContainer::value_type) == 1,
                             bool> = true>
  /* implicit */ ByteContainerView(const ByteContainer &u)
      : Span(reinterpret_cast<const uint8_t *>(u.data()), u.size()) {}

  template <size_t N>
  explicit ByteContainerView(const char bytes[N]) : Span(&bytes[0], N) {}

  // Do not mark explicit, so pointer decay can happen
  /* implicit */ ByteContainerView(const char *s)
      : Span(reinterpret_cast<const uint8_t *>(s),
             s != nullptr ? std::strlen(s) : 0) {}

  explicit ByteContainerView(const Buffer &b)
      : Span(b.data<uint8_t>(), b.size()) {}

  bool operator==(const ByteContainerView &other) const {
    if (data() == other.data() && size() == other.size()) {
      return true;
    }
    if (size() == other.size()) {
      return std::memcmp(data(), other.data(), size()) == 0;
    }
    return false;
  }

  operator std::string_view() const {
    return empty() ? std::string_view()
                   : std::string_view(reinterpret_cast<const char *>(data()),
                                      size());
  }
};

}  // namespace yasl
