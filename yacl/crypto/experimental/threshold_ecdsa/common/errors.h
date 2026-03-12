// Copyright 2026 Ant Group Co., Ltd.
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

#include "yacl/base/exception.h"

// Use YACL-style exceptions with a safe "{}" wrapper so dynamic messages are
// treated as plain text instead of runtime format strings.
#define TECDSA_THROW(msg) YACL_THROW("{}", (msg))
#define TECDSA_THROW_ARGUMENT(msg) YACL_THROW_ARGUMENT_ERROR("{}", (msg))
#define TECDSA_THROW_LOGIC(msg) YACL_THROW_LOGIC_ERROR("{}", (msg))
#define TECDSA_ENFORCE(cond, msg) YACL_ENFORCE((cond), "{}", (msg))
