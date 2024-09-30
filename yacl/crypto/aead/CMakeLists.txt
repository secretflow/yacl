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

set(YACL_SOURCE_FILES ${YACL_SOURCE_FILES} ${CMAKE_CURRENT_LIST_DIR}/all_gcm.cc
                      ${CMAKE_CURRENT_LIST_DIR}/sm4_mte.cc)

# Add header files for installation
install(FILES ${CMAKE_CURRENT_LIST_DIR}/all_gcm.h
              ${CMAKE_CURRENT_LIST_DIR}/sm4_mte.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/yacl/crypto/aead)

set(YACL_SOURCE_FILES
    ${YACL_SOURCE_FILES}
    PARENT_SCOPE)

add_executable(all_gcm_test all_gcm_test.cc)
target_link_libraries(all_gcm_test PRIVATE yacl gtest_main)
add_test(NAME all_gcm_test COMMAND all_gcm_test)

add_executable(sm4_mte_test sm4_mte_test.cc)
target_link_libraries(sm4_mte_test PRIVATE yacl gtest_main)
add_test(NAME sm4_mte_test COMMAND sm4_mte_test)
