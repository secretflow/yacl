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

set(YACL_SOURCE_FILES
    ${YACL_SOURCE_FILES} ${CMAKE_CURRENT_LIST_DIR}/rsa_signing.cc
    ${CMAKE_CURRENT_LIST_DIR}/sm2_signing.cc)

# Add header files for installation
install(
  FILES ${CMAKE_CURRENT_LIST_DIR}/rsa_signing.h
        ${CMAKE_CURRENT_LIST_DIR}/signing.h
        ${CMAKE_CURRENT_LIST_DIR}/sm2_signing.h
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/yacl/crypto/sign)

set(YACL_SOURCE_FILES
    ${YACL_SOURCE_FILES}
    PARENT_SCOPE)

add_executable(rsa_signing_test rsa_signing_test.cc)
target_link_libraries(rsa_signing_test PRIVATE yacl gtest_main)
target_link_options(rsa_signing_test PRIVATE "-all_load") # for spi
add_test(NAME rsa_signing_test COMMAND rsa_signing_test)

add_executable(sm2_signing_test sm2_signing_test.cc)
target_link_libraries(sm2_signing_test PRIVATE yacl gtest_main)
target_link_options(sm2_signing_test PRIVATE "-all_load") # for spi
add_test(NAME sm2_signing_test COMMAND sm2_signing_test)
