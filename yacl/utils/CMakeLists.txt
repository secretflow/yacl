# Copyright 2024 Ant Group Co., Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set(YACL_SOURCE_FILES ${YACL_SOURCE_FILES}
    ${CMAKE_CURRENT_LIST_DIR}/parallel.cc
    ${CMAKE_CURRENT_LIST_DIR}/thread_pool.cc
)

# Add header files for installation
install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/parallel.h
        ${CMAKE_CURRENT_LIST_DIR}/thread_pool.h
    DESTINATION
        ${CMAKE_INSTALL_INCLUDEDIR}/yacl/utils
)

set(YACL_SOURCE_FILES ${YACL_SOURCE_FILES} PARENT_SCOPE)

add_executable(parallel_test parallel_test.cc)
target_link_libraries(parallel_test PRIVATE yacl gtest_main)
add_test(NAME parallel_test COMMAND parallel_test)
