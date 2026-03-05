#include "yacl/crypto/experimental/threshold_ecdsa/crypto/random.h"
#include "yacl/crypto/experimental/threshold_ecdsa/common/errors.h"

#include <limits>
#include <stdexcept>

#include <openssl/rand.h>

namespace tecdsa {

Bytes Csprng::RandomBytes(size_t size) {
  Bytes out(size);
  if (size == 0) {
    return out;
  }

  if (size > static_cast<size_t>(std::numeric_limits<int>::max())) {
    TECDSA_THROW("RAND_bytes size exceeds INT_MAX");
  }

  if (RAND_bytes(out.data(), static_cast<int>(size)) != 1) {
    TECDSA_THROW("RAND_bytes failed");
  }
  return out;
}

Scalar Csprng::RandomScalar() {
  while (true) {
    const Bytes bytes = RandomBytes(32);
    try {
      return Scalar::FromCanonicalBytes(bytes);
    } catch (const std::invalid_argument&) {
      continue;
    }
  }
}

}  // namespace tecdsa
