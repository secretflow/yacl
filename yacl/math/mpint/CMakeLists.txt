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
    ${YACL_SOURCE_FILES}
    ${CMAKE_CURRENT_LIST_DIR}/montgomery_math.cc
    ${CMAKE_CURRENT_LIST_DIR}/mp_int.cc
    ${CMAKE_CURRENT_LIST_DIR}/tommath_ext_types.cc
    ${CMAKE_CURRENT_LIST_DIR}/tommath_ext_features.cc)

# Add header files for installation
install(
  FILES ${CMAKE_CURRENT_LIST_DIR}/montgomery_math.h
        ${CMAKE_CURRENT_LIST_DIR}/mp_int.h
        ${CMAKE_CURRENT_LIST_DIR}/mp_int_enforce.h
        ${CMAKE_CURRENT_LIST_DIR}/tommath_ext_types.h
        ${CMAKE_CURRENT_LIST_DIR}/tommath_ext_features.h
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/yacl/math/mpint)

set(YACL_SOURCE_FILES
    ${YACL_SOURCE_FILES}
    PARENT_SCOPE)

add_executable(montgomery_math_test montgomery_math_test.cc)
target_link_libraries(montgomery_math_test PRIVATE yacl gtest_main)
add_test(NAME montgomery_math_test COMMAND montgomery_math_test)

add_executable(mp_int_test mp_int_test.cc)
target_link_libraries(mp_int_test PRIVATE yacl gtest_main)
add_test(NAME mp_int_test COMMAND mp_int_test)

add_executable(tommath_ext_test tommath_ext_test.cc)
target_link_libraries(tommath_ext_test PRIVATE yacl gtest_main)
add_test(NAME tommath_ext_test COMMAND
tommath_ext_test)

# TODO add benchmark target
