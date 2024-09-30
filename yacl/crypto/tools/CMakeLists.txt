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
    ${YACL_SOURCE_FILES} ${CMAKE_CURRENT_LIST_DIR}/crhash.cc
    ${CMAKE_CURRENT_LIST_DIR}/prg.cc ${CMAKE_CURRENT_LIST_DIR}/rp.cc)

# Add header files for installation
install(
  FILES ${CMAKE_CURRENT_LIST_DIR}/common.h ${CMAKE_CURRENT_LIST_DIR}/crhash.h
        ${CMAKE_CURRENT_LIST_DIR}/prg.h ${CMAKE_CURRENT_LIST_DIR}/ro.h
        ${CMAKE_CURRENT_LIST_DIR}/rp.h
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/yacl/crypto/tools)

set(YACL_SOURCE_FILES
    ${YACL_SOURCE_FILES}
    PARENT_SCOPE)

add_executable(crhash_test crhash_test.cc)
target_link_libraries(crhash_test PRIVATE yacl gtest_main)
add_test(NAME crhash_test COMMAND crhash_test)

add_executable(prg_test prg_test.cc)
target_link_libraries(prg_test PRIVATE yacl gtest_main)
add_test(NAME prg_test COMMAND prg_test)

add_executable(ro_test ro_test.cc)
target_link_libraries(ro_test PRIVATE yacl gtest_main)
add_test(NAME ro_test COMMAND ro_test)

add_executable(rp_test rp_test.cc)
target_link_libraries(rp_test PRIVATE yacl gtest_main)
add_test(NAME rp_test COMMAND rp_test)

# TODO add benchmark target
