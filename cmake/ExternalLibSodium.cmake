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

# NOTE download. configure, build, install happens during project make process
ExternalProject_Add(
  libsodium
  PREFIX "external_libsodium"
  URL https://github.com/jedisct1/libsodium/releases/download/1.0.18-RELEASE/libsodium-1.0.18.tar.gz
  URL_HASH
    SHA256=6f504490b342a4f8a4c4a02fc9b866cbef8622d5df4e5452b46be121e46636c1
  BUILD_IN_SOURCE true
  CONFIGURE_COMMAND ./configure --prefix=${CMAKE_BINARY_DIR}
  BUILD_COMMAND make
  INSTALL_COMMAND make install
  EXCLUDE_FROM_ALL)

add_library(ExtLibsodium STATIC IMPORTED)
set_target_properties(
  ExtLibsodium PROPERTIES IMPORTED_LOCATION
                          ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libsodium.a)
add_library(ExtLibsodium::libsodium ALIAS ExtLibsodium)

ExternalProject_Get_Property(libsodium SOURCE_DIR)
include_directories(${SOURCE_DIR}/src/libsodium/include)
include_directories(${SOURCE_DIR}/src/libsodium/include/sodium)
unset(SOURCE_DIR)
