#pragma once

#include "yasl/crypto/drbg/entropy_source.h"

namespace yasl::crypto {

std::shared_ptr<IEntropySource> makeEntropySource();

}