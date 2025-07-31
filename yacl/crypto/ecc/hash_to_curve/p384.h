// Copyright 2025 Guan Yewei
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

#include <string>

#include "yacl/base/byte_container_view.h"
#include "yacl/crypto/ecc/ec_point.h"

namespace yacl {

// EncodeToCurve for P-384
crypto::EcPoint EncodeToCurveP384(yacl::ByteContainerView buffer,
                                  const std::string &dst);

// HashToScalar for P-384
crypto::MPInt HashToScalarP384(yacl::ByteContainerView buffer,
                               const std::string &dst);

}  // namespace yacl
