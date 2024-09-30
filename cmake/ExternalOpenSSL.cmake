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

# Trying to find system openssl first (failures are allowed)
find_package(OpenSSL)

# if not found, or version not supoprted
if(${OPENSSL_FOUND} AND ${OPENSSL_VERSION} VERSION_LESS "5.0.0")
  message("Yacl does not support ${OPENSSL_VERSION}, using downloaded openssl")
  ExternalProject_Add(
    OpenSSL
    PREFIX "external_openssl"
    URL https://github.com/openssl/openssl/archive/refs/tags/openssl-3.3.2.tar.gz
    URL_HASH
      SHA256=bedbb16955555f99b1a7b1ba90fc97879eb41025081be359ecd6a9fcbdf1c8d2
    DOWNLOAD_NO_PROGRESS true
    BUILD_IN_SOURCE true
    CONFIGURE_COMMAND
      ./Configure no-legacy no-weak-ssl-ciphers no-tests no-shared no-ui-console
      no-docs --prefix=${CMAKE_BINARY_DIR}
    INSTALL_COMMAND make install)

  # see: https://cmake.org/cmake/help/v3.4/module/FindOpenSSL.html
  set(OPENSSL_USE_STATIC_LIBS TRUE)
  find_package(OpenSSL REQUIRED)

else()
  message("using system openssl")
endif()
