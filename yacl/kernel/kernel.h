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

// Kernel interface class
class Kernel {
 public:
  enum class Kind {
    SingleThread,  // supports eval
    MultiThread,   // supports eval, eval_multithread
    Streaming      // supports eval, eval_multithread, and eval_streaming
  };

  virtual ~Kernel() = default;

  virtual Kind kind() const = 0;

  // virtual void latency();

  // virtual void comm();

  // virtual void eval() = 0;
};

// Single-thread kernel
class SingleThreadKernel : public Kernel {
 public:
  Kind kind() const override { return Kind::SingleThread; }

  // virtual void eval(/* kernel-specific args*/) = 0;
};

// Multi-thread kernel
class MultiThreadKernel : public Kernel {
 public:
  Kind kind() const override { return Kind::MultiThread; }
  // virtual void eval_multithread(/* kernel-specific args*/) = 0;
};

// Streaming kernel
class StreamingKernel : public Kernel {
 public:
  Kind kind() const override { return Kind::Streaming; }
  // virtual void eval_streaming(/* kernel-specific args*/) = 0;
};

}  // namespace yacl::crypto
