// Copyright 2023 Ant Group Co., Ltd.
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

#include <memory>

#include "yacl/link/context.h"

namespace yacl::crypto {

class Kernel {
 public:
  enum class Kind { SingleThread, MultiThread };

  virtual ~Kernel() = default;

  virtual Kind kind() const = 0;

  // virtual void latency();

  // virtual void comm();

  // virtual void eval();
};

// Stream kernel
class StreamKernel : public Kernel {
 public:
  Kind kind() const override { return Kind::SingleThread; }
};

}  // namespace yacl::crypto
