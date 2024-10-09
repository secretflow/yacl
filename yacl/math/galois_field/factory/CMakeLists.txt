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
    ${CMAKE_CURRENT_LIST_DIR}/gf_spi.cc
    ${CMAKE_CURRENT_LIST_DIR}/mcl_factory.cc
    # ${CMAKE_CURRENT_LIST_DIR}/intel_factory.cc
    ${CMAKE_CURRENT_LIST_DIR}/mpint_factory.cc)

# Add header files for installation
install(
  FILES ${CMAKE_CURRENT_LIST_DIR}/gf_scalar.h
        ${CMAKE_CURRENT_LIST_DIR}/gf_vector.h
        ${CMAKE_CURRENT_LIST_DIR}/gf_spi.h
        ${CMAKE_CURRENT_LIST_DIR}/mcl_factory.h
        ${CMAKE_CURRENT_LIST_DIR}/intel_factory.h
        ${CMAKE_CURRENT_LIST_DIR}/mpint_factory.h
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/yacl/math/galois_field/factory)

set(YACL_SOURCE_FILES
    ${YACL_SOURCE_FILES}
    PARENT_SCOPE)

add_executable(mcl_factory_test mcl_factory_test.cc)
target_link_libraries(mcl_factory_test PRIVATE yacl gtest_main)
add_test(NAME mcl_factory_test COMMAND mcl_factory_test)

add_executable(mpint_factory_test mpint_factory_test.cc)
target_link_libraries(mpint_factory_test PRIVATE yacl gtest_main)
add_test(NAME mpint_factory_test COMMAND mpint_factory_test)

# add_executable(intel_factory_test intel_factory_test.cc)
# target_link_libraries(intel_factory_test PRIVATE yacl gtest_main)
# add_test(NAME intel_factory_test COMMAND intel_factory_test)
