#pragma once

#include <string>

#include "yacl/base/byte_container_view.h"

// EncodeToCurve for P-256
std::vector<uint8_t> EncodeToCurveP256(yacl::ByteContainerView buffer,
                                       const std::string &dst);
