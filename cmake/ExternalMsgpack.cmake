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

FetchContent_Declare(msgpack
                     URL https://github.com/msgpack/msgpack-c/archive/refs/tags/cpp-6.1.0.tar.gz
                     URL_HASH SHA256=5e63e4d9b12ab528fccf197f7e6908031039b1fc89cd8da0e97fbcbf5a6c6d3a
                    )

SET(MSGPACK_CXX17 ON CACHE INTERNAL "")
SET(MSGPACK_USE_BOOST OFF CACHE INTERNAL "")
SET(MSGPACK_BUILD_EXAMPLES OFF CACHE INTERNAL "")
SET(BUILD_SHARED_LIBS OFF CACHE INTERNAL "")
SET(MSGPACK_BUILD_TESTS OFF CACHE INTERNAL "")

FetchContent_MakeAvailable(msgpack)

add_definitions(-DMSGPACK_NO_BOOST)
include_directories(${msgpack_SOURCE_DIR}/include)

