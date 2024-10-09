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
  libtommath
  PREFIX "external_libtommath"
  URL https://github.com/libtom/libtommath/archive/42b3fb07e7d504f61a04c7fca12e996d76a25251.tar.gz
  URL_HASH
    SHA256=7cfbdb64431129de4257e7d3349200fdbd4f229b470ff3417b30d0f39beed41f
  INSTALL_COMMAND cmake --install . --prefix ${CMAKE_BINARY_DIR}
  EXCLUDE_FROM_ALL)

add_library(ExtLibtommath STATIC IMPORTED)
set_target_properties(
  ExtLibtommath PROPERTIES IMPORTED_LOCATION
                           ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libtommath.a)

add_library(ExtLibtommath::libtommath ALIAS ExtLibtommath)

ExternalProject_Get_Property(libtommath SOURCE_DIR)
include_directories(${SOURCE_DIR}/..)
unset(SOURCE_DIR)
