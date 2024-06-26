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

void InitializeConfig();

uint32_t GetSubBytesAsUint32(const yacl::Buffer& bytes, size_t start,
                             size_t end);

extern int Ilen;
extern int Imax;
extern int Jlen;
extern int Jmax;
extern uint32_t Cuckoolen;
extern int L1;  // 1<< Ilen
extern int L2;  // 1<< Ilen
extern int Treelen;
extern int TestNum;
extern uint64_t Mmax;
