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

set(YACL_SOURCE_FILES ${YACL_SOURCE_FILES}
                      ${CMAKE_CURRENT_LIST_DIR}/symmetric_crypto.cc)

# Add header files for installation
install(FILES ${CMAKE_CURRENT_LIST_DIR}/symmetric_crypto.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/yacl/crypto/block_cipher)

set(YACL_SOURCE_FILES
    ${YACL_SOURCE_FILES}
    PARENT_SCOPE)

add_executable(symmetric_crypto_test symmetric_crypto_test.cc)
target_link_libraries(symmetric_crypto_test PRIVATE yacl gtest_main)
add_test(NAME symmetric_crypto_test COMMAND symmetric_crypto_test)
