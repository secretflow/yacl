// Copyright 2025 Ant Group Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

#include <string_view>

#include "yacl/base/byte_container_view.h"
#include "yacl/crypto/ecc/ec_point.h"
#include "yacl/math/mpint/mp_int.h"

namespace yacl {

// RFC 9380 hash-to-curve for Ristretto255
crypto::EcPoint EncodeToCurveRistretto255(yacl::ByteContainerView buffer,
                                          std::string_view dst);

crypto::EcPoint HashToCurveRistretto255(yacl::ByteContainerView buffer,
                                        std::string_view dst);

math::MPInt HashToScalarRistretto255(yacl::ByteContainerView buffer,
                                     std::string_view dst);

}  // namespace yacl
