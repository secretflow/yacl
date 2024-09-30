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

ExternalProject_Add(
  sse2neon
  PREFIX "external_sse2neon"
  URL https://github.com/DLTcollab/sse2neon/archive/8df2f48dbd0674ae5087f7a6281af6f55fa5a8e2.tar.gz
  URL_HASH
    SHA256=787e0a7a64f1461b48232a7f9b9e9c14fa4a35a30875f2fb91aec6ddeaddfc0f
  DOWNLOAD_NO_PROGRESS true
  BUILD_IN_SOURCE true
  CONFIGURE_COMMAND ""
  INSTALL_COMMAND "")

ExternalProject_Get_Property(sse2neon SOURCE_DIR)
include_directories(${SOURCE_DIR})
unset(${SOURCE_DIR})
