# Copyright 2024 Ant Group Co., Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

FetchContent_Declare(
    abseil
    URL https://github.com/abseil/abseil-cpp/archive/refs/tags/20240722.0.tar.gz
    URL_HASH SHA256=f50e5ac311a81382da7fa75b97310e4b9006474f9560ac46f54a9967f07d4ae3
)

SET(ABSL_PROPAGATE_CXX_STD ON CACHE INTERNAL "")
SET(ABSL_USE_SYSTEM_INCLUDES ON CACHE INTERNAL "")
FetchContent_MakeAvailable(abseil)

include_directories(${abseil_SOURCE_DIR})
