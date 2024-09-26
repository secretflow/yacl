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

FetchContent_Declare(gflags
                     URL https://github.com/gflags/gflags/archive/v2.2.2.tar.gz
                     URL_HASH SHA256=34af2f15cf7367513b352bdcd2493ab14ce43692d2dcd9dfc499492966c64dcf
                    )

set(CMAKE_CXX_FLAGS_OLD "${CMAKE_CXX_FLAGS}")

# Add other flags here.
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-unused-parameter")
set(BUILD_TESTING OFF CACHE INTERNAL "")

FetchContent_MakeAvailable(gflags)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS_OLD}")
unset(BUILD_TESTING)
