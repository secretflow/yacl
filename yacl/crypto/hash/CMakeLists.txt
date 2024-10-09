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
    ${YACL_SOURCE_FILES} ${CMAKE_CURRENT_LIST_DIR}/ssl_hash.cc
    ${CMAKE_CURRENT_LIST_DIR}/blake3.cc
    ${CMAKE_CURRENT_LIST_DIR}/hash_utils.cc)

# Add header files for installation
install(
  FILES ${CMAKE_CURRENT_LIST_DIR}/ssl_hash.h
        ${CMAKE_CURRENT_LIST_DIR}/hash_interface.h
        ${CMAKE_CURRENT_LIST_DIR}/hash_utils.h
        ${CMAKE_CURRENT_LIST_DIR}/blake3.h
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/yacl/crypto/hash)

set(YACL_SOURCE_FILES
    ${YACL_SOURCE_FILES}
    PARENT_SCOPE)

add_executable(blake3_test blake3_test.cc)
target_link_libraries(blake3_test PRIVATE yacl gtest_main)
add_test(NAME blake3_test COMMAND blake3_test)

add_executable(ssl_hash_all_test ssl_hash_all_test.cc)
target_link_libraries(ssl_hash_all_test PRIVATE yacl gtest_main)
add_test(NAME ssl_hash_all_test COMMAND ssl_hash_all_test)

# TODO add benchmark target
