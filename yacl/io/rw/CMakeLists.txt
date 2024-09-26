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
    ${CMAKE_CURRENT_LIST_DIR}/csv_reader.cc
    ${CMAKE_CURRENT_LIST_DIR}/csv_writer.cc
    ${CMAKE_CURRENT_LIST_DIR}/mmapped_file.cc
)

# Add header files for installation
install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/csv_reader.h
        ${CMAKE_CURRENT_LIST_DIR}/csv_writer.h
        ${CMAKE_CURRENT_LIST_DIR}/mmapped_file.h
        ${CMAKE_CURRENT_LIST_DIR}/reader.h
        ${CMAKE_CURRENT_LIST_DIR}/writer.h
        ${CMAKE_CURRENT_LIST_DIR}/schema.h
    DESTINATION
        ${CMAKE_INSTALL_INCLUDEDIR}/yacl/io/stream
)

set(YACL_SOURCE_FILES ${YACL_SOURCE_FILES} PARENT_SCOPE)

add_executable(rw_test rw_test.cc)
target_link_libraries(rw_test PRIVATE yacl gtest_main gflags)
add_test(NAME rw_test COMMAND rw_test WORKING_DIRECTORY ${PROJECT_SOURCE_DIR})
