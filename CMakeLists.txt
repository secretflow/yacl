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

cmake_minimum_required(VERSION 3.20)

project(
  yacl
  VERSION 0.4.5
  DESCRIPTION
    "YACL (Yet Another Common crypto library) is a C++ library that contains cryptography, network and io modules which other SecretFlow code depends on."
  HOMEPAGE_URL "https://github.com/secretflow/yacl"
  LANGUAGES CXX C)

set(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake/")
set(CMAKE_EXPORT_COMPILE_COMMANDS TRUE)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE
      "Release"
      CACHE STRING "Build type" FORCE)
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Release" "Debug"
                                               "MinSizeRel" "RelWithDebInfo")
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
include(ExternalProject)

# Always build position-independent-code
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Enable C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED YES)
set(CMAKE_EXE_LINKER_FLAGS
    "${CMAKE_EXE_LINKER_FLAGS} -undefined dynamic_lookup")

include(GNUInstallDirs)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/${CMAKE_INSTALL_LIBDIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/${CMAKE_INSTALL_LIBDIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/${CMAKE_INSTALL_BINDIR})

include(AddCompilerFlags)

# make it colorful under ninja-build
if(CMAKE_GENERATOR STREQUAL Ninja)
  add_compiler_flags(-fdiagnostics-color=always)
endif()

# set fetch content base directory
set(FETCHCONTENT_BASE_DIR ${CMAKE_BINARY_DIR}/external_cmake)

include(ExternalAbseil)
include(ExternalBlake3)
include(ExternalFmt)
include(ExternalSPDLog)
include(ExternalGTest)
include(ExternalGflags)
include(ExternalMsgpack)
include(ExternalOpenSSL)
include(ExternalLibtommath)
include(ExternalSse2neon)
include(ExternalMcl)
include(ExternalFourQ)
include(ExternalLibSodium)

enable_testing()

add_library(yacl STATIC)

target_include_directories(
  yacl
  PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}>" # these dirs are only used
                                                   # when building inside the
                                                   # build tree
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>" # these dirs are only
                                                       # used when linking
                                                       # against a prebuilt
                                                       # version of your package
)

target_include_directories(yacl PUBLIC ${CMAKE_BINARY_DIR}/include)

set(YACL_SOURCE_FILES "")

add_subdirectory(yacl)
add_subdirectory(yacl/base)
add_subdirectory(yacl/crypto)
add_subdirectory(yacl/io)
add_subdirectory(yacl/utils)
add_subdirectory(yacl/math)

target_sources(yacl PRIVATE ${YACL_SOURCE_FILES})

target_link_libraries(
  yacl
  PUBLIC fmt::fmt
         absl::stacktrace
         absl::symbolize
         absl::int128
         BLAKE3::blake3
         mcl::mcl
         ExtLibsodium::libsodium
         ExtLibtommath::libtommath
         ExtFourQ::fourq)

if(YACL_WITH_EXT_OPENSSL)
  target_link_libraries(yacl PUBLIC ExtOpenSSL::Crypto ExtOpenSSL::SSL)
else()
  target_link_libraries(yacl PUBLIC OpenSSL::Crypto OpenSSL::SSL)
endif()
