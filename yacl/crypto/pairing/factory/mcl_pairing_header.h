// Copyright 2023 Ant Group Co., Ltd.
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

// Bls
// BLS12-381 ; sizeof(Fp) = 48, sizeof(Fr) = 32
#include "mcl/bls12_381.hpp"

// Method from https://github.com/herumi/mcl/blob/master/sample/multi.cpp
//
// Other pairing curves maybe not standard and just for test purpose And
// libmcl's author herumi doesn't recommend this.
// https://github.com/herumi/mcl/issues/181#issuecomment-1513916051

// For MCL_BN_SNARK1
#undef MCL_INCLUDE_MCL_BN_HPP
#undef MCL_MAX_FP_BIT_SIZE
#undef MCL_MAX_FR_BIT_SIZE
#define MCL_MAX_FP_BIT_SIZE 256
#undef MCL_NAMESPACE_BN
#define MCL_NAMESPACE_BN bnsnark
#include "mcl/bn.hpp"

#ifdef MCL_ALL_PAIRING_FOR_YACL
// For MCL_BN254
#undef MCL_INCLUDE_MCL_BN_HPP
#undef MCL_MAX_FP_BIT_SIZE
#undef MCL_MAX_FR_BIT_SIZE
#define MCL_MAX_FP_BIT_SIZE 256
#undef MCL_NAMESPACE_BN
#define MCL_NAMESPACE_BN bn254
#include "mcl/bn.hpp"

// For MCL_BN381_1
#undef MCL_INCLUDE_MCL_BN_HPP
#undef MCL_MAX_FP_BIT_SIZE
#undef MCL_MAX_FR_BIT_SIZE
#define MCL_MAX_FP_BIT_SIZE 384
#undef MCL_NAMESPACE_BN
#define MCL_NAMESPACE_BN bn382m
#include "mcl/bn.hpp"

// For MCL_BN381_2
#undef MCL_INCLUDE_MCL_BN_HPP
#undef MCL_MAX_FP_BIT_SIZE
#undef MCL_MAX_FR_BIT_SIZE
#define MCL_MAX_FP_BIT_SIZE 384
#undef MCL_NAMESPACE_BN
#define MCL_NAMESPACE_BN bn382r
#include "mcl/bn.hpp"

#undef MCL_INCLUDE_MCL_BN_HPP
#undef MCL_MAX_FP_BIT_SIZE
#undef MCL_MAX_FR_BIT_SIZE
#define MCL_MAX_FP_BIT_SIZE 462
#undef MCL_NAMESPACE_BN
#define MCL_NAMESPACE_BN bn462
#include "mcl/bn.hpp"

// For MCL_BN160
#undef MCL_INCLUDE_MCL_BN_HPP
#undef MCL_MAX_FP_BIT_SIZE
#undef MCL_MAX_FR_BIT_SIZE
#define MCL_MAX_FP_BIT_SIZE 192
#undef MCL_NAMESPACE_BN
#define MCL_NAMESPACE_BN bn160
#include "mcl/bn.hpp"

// For MCL_BLS12_377
#undef MCL_INCLUDE_MCL_BN_HPP
#undef MCL_MAX_FP_BIT_SIZE
#undef MCL_MAX_FR_BIT_SIZE
#define MCL_MAX_FP_BIT_SIZE 384
#undef MCL_NAMESPACE_BN
#define MCL_NAMESPACE_BN bls123
#include "mcl/bn.hpp"

// For MCL_BLS12_461
#undef MCL_INCLUDE_MCL_BN_HPP
#undef MCL_MAX_FP_BIT_SIZE
#undef MCL_MAX_FR_BIT_SIZE
#define MCL_MAX_FP_BIT_SIZE 462
#undef MCL_NAMESPACE_BN
#define MCL_NAMESPACE_BN bls124
#include "mcl/bn.hpp"

// For MCL_BN_P256
#undef MCL_INCLUDE_MCL_BN_HPP
#undef MCL_MAX_FP_BIT_SIZE
#undef MCL_MAX_FR_BIT_SIZE
#define MCL_MAX_FP_BIT_SIZE 256
#undef MCL_NAMESPACE_BN
#define MCL_NAMESPACE_BN bn256
#include "mcl/bn.hpp"

#endif
