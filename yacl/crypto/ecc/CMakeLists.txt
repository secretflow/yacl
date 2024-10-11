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
    ${YACL_SOURCE_FILES} ${CMAKE_CURRENT_LIST_DIR}/curve_meta.cc
    ${CMAKE_CURRENT_LIST_DIR}/ec_point.cc ${CMAKE_CURRENT_LIST_DIR}/ecc_spi.cc
    ${CMAKE_CURRENT_LIST_DIR}/group_sketch.cc)

# Add header files for installation
install(
  FILES ${CMAKE_CURRENT_LIST_DIR}/curve_meta.h
        ${CMAKE_CURRENT_LIST_DIR}/ec_point.h
        ${CMAKE_CURRENT_LIST_DIR}/ecc_spi.h
        ${CMAKE_CURRENT_LIST_DIR}/group_sketch.h
        ${CMAKE_CURRENT_LIST_DIR}/any_ptr.h
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/yacl/crypto/ecc)

# add_subdirectory(benchmark) # TODO

add_subdirectory(FourQlib)
add_subdirectory(libsodium)
add_subdirectory(mcl)
add_subdirectory(openssl)
add_subdirectory(toy)

# TODO
# add_subdirectory(lib25519)

set(YACL_SOURCE_FILES
    ${YACL_SOURCE_FILES}
    PARENT_SCOPE)

add_executable(ecc_test ecc_test.cc)
target_link_libraries(ecc_test PRIVATE yacl gtest_main)
target_link_options(ecc_test PRIVATE "-all_load") # for spi
add_test(NAME ecc_test COMMAND ecc_test)
