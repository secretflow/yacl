#pragma once

#include <random>

#include "yasl/crypto/pseudo_random_generator.h"

namespace yasl {

// Create vector<bool> random choices.
inline std::vector<bool> CreateRandomChoices(size_t len) {
  std::random_device rd;
  PseudoRandomGenerator<unsigned> prg(rd());
  const unsigned stride = sizeof(unsigned) * 8;
  std::vector<bool> ret(len, false);
  for (size_t i = 0; i < len; i += stride) {
    unsigned rand = prg();
    unsigned size = std::min(stride, static_cast<unsigned>(len - i));
    for (unsigned j = 0; j < size; ++j) {
      ret[i + j] = (rand & (1 << j)) ? true : false;
    }
  }
  return ret;
}

// CreateRandomChoiceBits
//
// Each bit of the output `vector<T>` will be a random choice bit.
// The output is `sizeof(T)` bytes aligned.
// This version is more firendly when we we are doing bit-wise message. That is
// what GMW circuits wanted.
template <typename T, std::enable_if_t<std::is_scalar<T>::value, int> = 0>
inline std::vector<T> CreateRandomChoiceBits(size_t num) {
  std::random_device rd;
  PseudoRandomGenerator<T> prg(rd());
  // Align to sizeof(T).
  constexpr int kNumBits = sizeof(T) * 8;
  std::vector<T> ret((num + kNumBits - 1) / kNumBits);
  std::generate(ret.begin(), ret.end(), [&] { return prg(); });
  return ret;
}

}  // namespace yasl
