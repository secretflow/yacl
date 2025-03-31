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

#include <bits/stdc++.h>
#include <emmintrin.h>
#include <openssl/sha.h>

#include <cstdint>
#include <cstring>
#include <iostream>
#include <memory>
#include <random>

#include "yacl/math/mpint/mp_int.h"

using uint128_t = __uint128_t;

// get the Least Significant Bit of uint128_t
inline bool getLSB(const uint128_t& x) { return (x & 1) == 1; }
