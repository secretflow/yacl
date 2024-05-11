// Copyright 2024 Ant Group Co., Ltd.
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

extern "C" {
#include "crypto_multiscalar/ed25519/amd64-maax-p3/ge25519_unpack.h"
#include "crypto_nG/merged25519/amd64-maax/ge25519.h"
#include "include-build/ge25519_is_on_curve.h"
#include "include-build/ge25519_scalarmult.h"
#include "include-build/ge25519_sub.h"
};
