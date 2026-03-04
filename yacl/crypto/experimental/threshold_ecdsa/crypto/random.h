#pragma once

#include <cstddef>

#include "yacl/crypto/experimental/threshold_ecdsa/common/bytes.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/scalar.h"

namespace tecdsa {

class Csprng {
 public:
  static Bytes RandomBytes(size_t size);
  static Scalar RandomScalar();
};

}  // namespace tecdsa
