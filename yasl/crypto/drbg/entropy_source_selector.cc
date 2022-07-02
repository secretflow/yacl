#include "yasl/crypto/drbg/entropy_source_selector.h"
#include <memory>

#ifdef __x86_64
#include "yasl/crypto/drbg/intel_entropy_source.h"
#else
#include "yasl/crypto/drbg/std_entropy_source.h"
#endif

namespace yasl::crypto {

std::shared_ptr<IEntropySource> makeEntropySource() {
#ifdef __x86_64
    return std::make_shared<IntelEntropySource>();
#else
    return std::make_shared<StdEntropySource>();
#endif
}

}  // namespace yasl::crypto
