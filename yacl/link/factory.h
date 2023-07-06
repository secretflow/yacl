// Copyright 2019 Ant Group Co., Ltd.
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

#include "yacl/link/context.h"

namespace yacl::link {

class ILinkFactory {
 public:
  virtual ~ILinkFactory() = default;

  // create new link context
  virtual std::shared_ptr<Context> CreateContext(const ContextDesc& desc,
                                                 size_t self_rank) = 0;
};

/// builtin link context type, in memory link context.
class FactoryMem : public ILinkFactory {
 public:
  std::shared_ptr<Context> CreateContext(const ContextDesc& desc,
                                         size_t self_rank) override;
};

/// builtin link context type, brpc base link context.
class FactoryBrpc : public ILinkFactory {
 public:
  std::shared_ptr<Context> CreateContext(const ContextDesc& desc,
                                         size_t self_rank) override;
};

/// brpc base link context with blackbox service
class FactoryBrpcBlackBox : public ILinkFactory {
 public:
  std::shared_ptr<Context> CreateContext(const ContextDesc& desc,
                                         size_t self_rank) override;
  static void GetPartyNodeInfoFromEnv(std::vector<ContextDesc::Party>& parties,
                                      size_t& self_rank);
};

}  // namespace yacl::link
