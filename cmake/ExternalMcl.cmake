# Copyright 2024 Ant Group Co., Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License. You may obtain a copy of
# the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.

FetchContent_Declare(
  mcl
  URL https://github.com/herumi/mcl/archive/refs/tags/v1.99.tar.gz
  URL_HASH
    SHA256=5ff9702c1f1b021925d1334ca0a03c87783174075aeaf87801842d3c08b3d39e)

FetchContent_MakeAvailable(mcl)

include_directories(${mcl_SOURCE_DIR}/include)
