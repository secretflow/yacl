// Copyright 2024 Ant Group Co., Ltd.
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

#pragma once

#include <unordered_map>

#include "yacl/base/int128.h"
#include "yacl/crypto/experimental/dpf/ge2n.h"

/* submodules */
#include "yacl/crypto/tools/prg.h"

namespace yacl::crypto {

// Puncturable Psedu-Random Function (PPRF)
//
// NOTE: this algorithm is experimental, also, this implementation is not
// *Private* Puncturable Pseu-Random Function
//
struct PprfPuncKey {
  uint128_t punc_point;  // NOTE: PPRF does not protect the punctured index
  std::unordered_map<size_t, uint128_t> seeds;
};

// PPRF punctured key generation function. On input the prf_key and the
// punc_point (it is supposed to a positive integer that is smaller than M),
// outputs a PprfPuncKey.
template <size_t /* input bit num */ M, size_t /* output bit num */ N>
void PprfPunc(uint128_t prf_key, GE2n<M> punc_point, PprfPuncKey* out);

template <size_t /* input bit num */ M, size_t /* output bit num */ N>
void PprfPuncEval(const PprfPuncKey& punc_key, GE2n<M> point, GE2n<N>* out);

template <size_t /* input bit num */ M, size_t /* output bit num */ N>
void PprfEval(uint128_t prf_key, GE2n<M> point, GE2n<N>* out);

// ---------------------------------------------------------------------------
// PPRF with uint128_t support, the validation of point values will be checked
// by the constructor of GE2n<M>, there is no need to perform additional
// check.
// ---------------------------------------------------------------------------

template <size_t /* input bit num */ M, size_t /* output bit num */ N>
void PprfPunc(uint128_t prf_key, uint128_t punc_point, PprfPuncKey* out) {
  PprfPunc<M, N>(prf_key, GE2n<M>(punc_point), out);
}

template <size_t /* input bit num */ M, size_t /* output bit num */ N>
void PprfPuncEval(const PprfPuncKey& punc_key, uint128_t point, GE2n<N>* out) {
  PprfPuncEval<M, N>(punc_key, GE2n<M>(point), out);
}

template <size_t /* input bit num */ M, size_t /* output bit num */ N>
void PprfEval(uint128_t prf_key, uint128_t point, GE2n<N>* out) {
  PprfEval<M, N>(prf_key, GE2n<M>(point), out);
}

}  // namespace yacl::crypto
