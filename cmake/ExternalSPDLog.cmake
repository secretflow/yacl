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

FetchContent_Declare(spdlog
                     URL https://github.com/gabime/spdlog/archive/refs/tags/v1.14.1.tar.gz
                     URL_HASH SHA256=1586508029a7d0670dfcb2d97575dcdc242d3868a259742b69f100801ab4e16b
                    )

SET(SPDLOG_BUILD_EXAMPLE OFF CACHE INTERNAL "")
SET(SPDLOG_FMT_EXTERNAL ON CACHE INTERNAL "")
SET(SPDLOG_NO_TLS ON CACHE INTERNAL "")
SET(SPDLOG_BUILD_PIC ON CACHE INTERNAL "")

FetchContent_MakeAvailable(spdlog)

include_directories(${spdlog_SOURCE_DIR}/include)
add_definitions(-DSPDLOG_FMT_EXTERNAL)
