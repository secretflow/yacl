// Copyright 2023 Ant Group Co., Ltd.
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

// code from https://stackoverflow.com/a/70994249

#pragma once

#include <cstddef>
#include <limits>
#include <new>
#include <vector>

namespace yacl {
/**
 * Returns aligned pointers when allocations are requested. Default alignment
 * is 64B = 512b, sufficient for AVX-512 and most cache line sizes.
 *
 * @tparam ALIGNMENT_IN_BYTES Must be a positive power of 2.
 */
template <typename ElementType, std::size_t ALIGNMENT_IN_BYTES = 64>
class UninitAlignedAllocator {
 private:
  static_assert(
      ALIGNMENT_IN_BYTES >= alignof(ElementType),
      "Beware that types like int have minimum alignment requirements "
      "or access will result in crashes.");

 public:
  using value_type = ElementType;
  static std::align_val_t constexpr ALIGNMENT{ALIGNMENT_IN_BYTES};

  /**
   * This is only necessary because UninitAlignedAllocator has a second template
   * argument for the alignment that will make the default
   * std::allocator_traits implementation fail during compilation.
   * @see https://stackoverflow.com/a/48062758/2191065
   */
  template <class OtherElementType>
  struct rebind {
    using other = UninitAlignedAllocator<OtherElementType, ALIGNMENT_IN_BYTES>;
  };

  constexpr UninitAlignedAllocator() noexcept = default;

  constexpr UninitAlignedAllocator(const UninitAlignedAllocator&) noexcept =
      default;

  template <typename U>
  constexpr UninitAlignedAllocator(
      UninitAlignedAllocator<U, ALIGNMENT_IN_BYTES> const&) noexcept {}

  [[nodiscard]] ElementType* allocate(std::size_t nElementsToAllocate) {
    if (nElementsToAllocate >
        std::numeric_limits<std::size_t>::max() / sizeof(ElementType)) {
      throw std::bad_array_new_length();
    }

    auto const nBytesToAllocate = nElementsToAllocate * sizeof(ElementType);
    return reinterpret_cast<ElementType*>(
        ::operator new[](nBytesToAllocate, ALIGNMENT));
  }

  void deallocate(ElementType* allocatedPointer,
                  [[maybe_unused]] std::size_t nBytesAllocated) {
    /* According to the C++20 draft n4868 § 17.6.3.3, the delete operator
     * must be called with the same alignment argument as the new expression.
     * The size argument can be omitted but if present must also be equal to
     * the one used in new. */
    ::operator delete[](allocatedPointer, ALIGNMENT);
  }

  /*
   * unintialised_allocator implementation (avoid meaningless initialization)
   * ref: https://stackoverflow.com/a/15966795
   */
  // elide trivial default construction of objects of type ElementType only
  template <typename U>
  typename std::enable_if<
      std::is_same<ElementType, U>::value &&
      std::is_trivially_default_constructible<U>::value>::type
  construct(U*) {}

  // elide trivial default destruction of objects of type ElementType only
  template <typename U>
  typename std::enable_if<std::is_same<ElementType, U>::value &&
                          std::is_trivially_destructible<U>::value>::type
  destroy(U*) {}
};

template <typename T, std::size_t ALIGNMENT_IN_BYTES = 16>
using UninitAlignedVector =
    std::vector<T, UninitAlignedAllocator<T, ALIGNMENT_IN_BYTES> >;

template <typename T, std::size_t A>
bool operator==(UninitAlignedAllocator<T, A> const& a0,
                UninitAlignedAllocator<T, A> const& a1) {
  return a0.ALIGNMENT == a1.ALIGNMENT;
}

template <typename T, size_t A>
bool operator!=(UninitAlignedAllocator<T, A> const& a0,
                UninitAlignedAllocator<T, A> const& a1) {
  return !(a0 == a1);
}
}  // namespace yacl
