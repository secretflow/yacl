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

set(YACL_EXT_OPENSSL_VERSION 3.3.2)
set(YACL_EXT_OPENSSL_URL
    https://github.com/openssl/openssl/archive/refs/tags/openssl-3.3.2.tar.gz)
set(YACL_EXT_OPENSSL_SHA256
    bedbb16955555f99b1a7b1ba90fc97879eb41025081be359ecd6a9fcbdf1c8d2)
set(YACL_WITH_EXT_OPENSSL TRUE)

# Trying to find system openssl first (failures are allowed) see:
# https://cmake.org/cmake/help/v3.4/module/FindOpenSSL.html
find_package(OpenSSL QUIET)

if(${OPENSSL_FOUND} AND ${OPENSSL_VERSION} VERSION_GREATER "5.0.0")
  message(STATUS "Found system OpenSSL (${OPENSSL_VERSION})")
  set(YACL_WITH_EXT_OPENSSL FALSE)
else()
  message(STATUS "OpenSSL not found, or its version is incompatiable")
  message(STATUS "Use downloaded OpenSSL (${YACL_EXT_OPENSSL_VERSION}) instead")
  set(YACL_WITH_EXT_OPENSSL TRUE)
endif()

if(YACL_WITH_EXT_OPENSSL)
  ExternalProject_Add(
    openssl
    PREFIX "external_openssl"
    URL ${YACL_EXT_OPENSSL_URL}
    URL_HASH SHA256=${YACL_EXT_OPENSSL_SHA256}
    BUILD_IN_SOURCE true
    CONFIGURE_COMMAND
      ./Configure no-legacy no-weak-ssl-ciphers no-tests no-shared no-ui-console
      no-docs no-apps --banner=Finished --release --prefix=${CMAKE_BINARY_DIR}
      -w
    BUILD_COMMAND make -j4 build_sw
    INSTALL_COMMAND make install_sw
    EXCLUDE_FROM_ALL)

  add_library(ExtOpenSSL_Crypto STATIC IMPORTED)
  set_target_properties(
    ExtOpenSSL_Crypto PROPERTIES IMPORTED_LOCATION
                                 ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libcrypto.a)
  add_library(ExtOpenSSL::Crypto ALIAS ExtOpenSSL_Crypto)

  add_library(ExtOpenSSL_SSL STATIC IMPORTED)
  set_target_properties(
    ExtOpenSSL_SSL PROPERTIES IMPORTED_LOCATION
                              ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libssl.a)
  add_library(ExtOpenSSL::SSL ALIAS ExtOpenSSL_SSL)
endif()
