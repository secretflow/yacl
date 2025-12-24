// Copyright 2025 Ant Group Co., Ltd.
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

#include "yacl/crypto/ecc/cuda/cuda_sm2_group.h"
#include "yacl/crypto/ecc/ecc_spi.h"

namespace yacl::crypto::cuda {

// Register CUDA SM2 implementation with the EcGroup factory
// Performance score: 500 (higher than OpenSSL's 100 for batch operations)
REGISTER_EC_LIBRARY("CUDA_SM2", 500, CudaSm2Group::IsSupported,
                    CudaSm2Group::Create);

}  // namespace yacl::crypto::cuda
