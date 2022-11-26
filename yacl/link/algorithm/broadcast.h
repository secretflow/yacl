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

#include "yacl/base/buffer.h"
#include "yacl/base/byte_container_view.h"
#include "yacl/link/context.h"

namespace yacl::link {

Buffer Broadcast(const std::shared_ptr<Context>& ctx, ByteContainerView input,
                 size_t root, std::string_view tag);

}  // namespace yacl::link
