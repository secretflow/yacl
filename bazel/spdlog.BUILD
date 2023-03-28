# Copyright 2022 Ant Group Co., Ltd.
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

load("@yacl//bazel:yacl.bzl", "yacl_cmake_external")

package(default_visibility = ["//visibility:public"])

filegroup(
    name = "all_srcs",
    srcs = glob(["**"]),
)

yacl_cmake_external(
    name = "spdlog",
    cache_entries = {
        "SPDLOG_BUILD_EXAMPLE": "OFF",
        "SPDLOG_FMT_EXTERNAL": "ON",
        "SPDLOG_NO_TLS": "ON",
        "CMAKE_INSTALL_LIBDIR": "lib",
        "SPDLOG_BUILD_PIC": "ON",
    },
    defines = [
        "SPDLOG_FMT_EXTERNAL",
        "SPDLOG_NO_TLS",
    ],
    lib_source = ":all_srcs",
    out_lib_dir = "lib",
    out_static_libs = select({
        "@yacl//bazel:yacl_build_as_debug": ["libspdlogd.a"],
        "//conditions:default": ["libspdlog.a"],
    }),
    deps = [
        "@com_github_fmtlib_fmt//:fmtlib",
    ],
)
