// Copyright 2024 Guowei Ling.
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

#include <cstdint>

#include "yacl/base/buffer.h"

namespace examples::hesm2 {

void InitializeConfig();

uint32_t GetSubBytesAsUint32(const yacl::Buffer& bytes, size_t start,
                             size_t end);

constexpr int Ilen = 12;           // l2-1
constexpr int Jlen = 20;           // l1-1
constexpr int Imax = 1 << Ilen;    // 1<< Ilen
constexpr int Jmax = 1 << Jlen;    // 1<<Jlen
constexpr int L1 = Jmax * 2;       // 1<< Ilen
constexpr int L2 = Imax * 2;       // 1<< Ilen
constexpr int Treelen = Imax * 2;  // imax*2
constexpr uint32_t Cuckoolen = static_cast<uint32_t>(Jmax * 1.3);
constexpr uint64_t Mmax =
    static_cast<uint64_t>(Imax) * static_cast<uint64_t>(L1) + Jmax;

}  // namespace examples::hesm2