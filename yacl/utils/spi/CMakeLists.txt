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
    ${CMAKE_CURRENT_LIST_DIR}/item.cc
    ${CMAKE_CURRENT_LIST_DIR}/argument/arg_kv.cc
    ${CMAKE_CURRENT_LIST_DIR}/argument/arg_set.cc
    ${CMAKE_CURRENT_LIST_DIR}/argument/argument.cc
    ${CMAKE_CURRENT_LIST_DIR}/argument/util.cc)

# Add header files for installation
install(
  FILES ${CMAKE_CURRENT_LIST_DIR}/item.h
        ${CMAKE_CURRENT_LIST_DIR}/spi_factory.h
        ${CMAKE_CURRENT_LIST_DIR}/type_traits.h
        ${CMAKE_CURRENT_LIST_DIR}/argument/arg_kv.h
        ${CMAKE_CURRENT_LIST_DIR}/sketch/scalar_call.h
        ${CMAKE_CURRENT_LIST_DIR}/sketch/scalar_define.h
        ${CMAKE_CURRENT_LIST_DIR}/sketch/scalar_tools.h
        ${CMAKE_CURRENT_LIST_DIR}/argument/arg_k.h
        ${CMAKE_CURRENT_LIST_DIR}/argument/arg_set.h
        ${CMAKE_CURRENT_LIST_DIR}/argument/argument.h
        ${CMAKE_CURRENT_LIST_DIR}/argument/util.h
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/yacl/utils/spi)

set(YACL_SOURCE_FILES
    ${YACL_SOURCE_FILES}
    PARENT_SCOPE)

add_executable(util_test argument/util_test.cc)
target_link_libraries(util_test PRIVATE yacl gtest_main)
add_test(NAME util_test COMMAND util_test)

add_executable(spi_factory_test spi_factory_test.cc)
target_link_libraries(spi_factory_test PRIVATE yacl gtest_main)
add_test(NAME
spi_factory_test COMMAND spi_factory_test)
