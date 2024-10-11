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

set(YACL_EXT_FOURQ_URL
    https://github.com/microsoft/FourQlib/archive/1031567f23278e1135b35cc04e5d74c2ac88c029.tar.gz
)

set(YACL_EXT_FOURQ_SHA256
    7417c829d7933facda568c7a08924dfefb0c83dd1dab411e597af4c0cc0417f0)

set(YACL_EXT_FOURQ_BUILD_COMMAND make ARCH=x64 GENERIC=TRUE EXTENDED_SET=FALSE
                                 -C FourQ_64bit_and_portable libFourQ)

set(YACL_EXT_FOURQ_INSTALL_COMMAND make PREFIX=${CMAKE_BINARY_DIR} -C
                                   FourQ_64bit_and_portable install)

ExternalProject_Add(
  fourq
  PREFIX "external_fourq"
  URL ${YACL_EXT_FOURQ_URL}
  URL_HASH SHA256=${YACL_EXT_FOURQ_SHA256}
  BUILD_IN_SOURCE true
  PATCH_COMMAND patch -p1 -l -i
                ${PROJECT_SOURCE_DIR}/bazel/patches/FourQlib.patch
  CONFIGURE_COMMAND "" # no configure
  BUILD_COMMAND ${YACL_EXT_FOURQ_BUILD_COMMAND}
  INSTALL_COMMAND ${YACL_EXT_FOURQ_INSTALL_COMMAND})

add_library(ExtFourQ STATIC IMPORTED)
set_target_properties(
  ExtFourQ PROPERTIES IMPORTED_LOCATION
                      ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libFourQ.a)
add_library(ExtFourQ::fourq ALIAS ExtFourQ)

ExternalProject_Get_Property(fourq SOURCE_DIR)
include_directories(${SOURCE_DIR}/FourQ_64bit_and_portable)
unset(SOURCE_DIR)

# HACK add yacl global compiler flag
add_compiler_flags("-D __LINUX__")
add_compiler_flags("-D _ARM64_")
