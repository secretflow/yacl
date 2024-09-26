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

cmake_minimum_required(VERSION 3.20)

project(
    yacl
    VERSION 0.4.5
    DESCRIPTION "YACL (Yet Another Common crypto library) is a C++ library that contains cryptography, network and io modules which other SecretFlow code depends on."
    HOMEPAGE_URL "https://github.com/secretflow/yacl"
    LANGUAGES CXX
)

set(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake/")

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY
        STRINGS "Release" "Debug" "MinSizeRel" "RelWithDebInfo")
endif()
message(STATUS "Build type (CMAKE_BUILD_TYPE): ${CMAKE_BUILD_TYPE}")

# This policy was introduced in CMake 3.13; OLD by default until CMake 3.21
cmake_policy(SET CMP0077 NEW)
cmake_policy(SET CMP0135 NEW)

# CMake modules
include(CMakeDependentOption)
include(CheckCXXCompilerFlag)
include(CheckCXXSourceRuns)
include(CheckLanguage)
include(FetchContent)

# Always build position-independent-code
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Enable C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED YES)

include(GNUInstallDirs)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY
  ${CMAKE_BINARY_DIR}/${CMAKE_INSTALL_LIBDIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY
  ${CMAKE_BINARY_DIR}/${CMAKE_INSTALL_LIBDIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY
  ${CMAKE_BINARY_DIR}/${CMAKE_INSTALL_BINDIR})


include(AddCompilerFlags)

# make it colorful under ninja-build
if (CMAKE_GENERATOR STREQUAL Ninja)
    add_compiler_flags(-fdiagnostics-color=always)
endif()

include(ExternalAbseil)
include(ExternalFmt)
include(ExternalSPDLog)
include(ExternalGTest)

enable_testing()

add_library(yacl STATIC)

target_include_directories (yacl 
    PUBLIC
        "$<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}>" # these dirs are only used when building inside the build tree
        "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>" # these dirs are only used when linking against a prebuilt version of your package
)

set(YACL_SOURCE_FILES "")

add_subdirectory(yacl/base)
add_subdirectory(yacl/utils)
add_subdirectory(yacl/io)

target_sources(yacl PRIVATE ${YACL_SOURCE_FILES})
target_link_libraries(yacl PRIVATE fmt::fmt absl::stacktrace absl::symbolize)
