# Copyright 2023 Ant Group Co., Ltd.
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

"""
wrapper bazel cc_xx to modify flags.
"""

load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_library", "cc_test")
load("@rules_foreign_cc//foreign_cc:defs.bzl", "cmake", "configure_make")

WARNING_FLAGS = [
    "-Wall",
    "-Wextra",
    "-Werror",
]

# set `SPDLOG_ACTIVE_LEVEL=1(SPDLOG_LEVEL_DEBUG)` to enable debug level log
DEBUG_FLAGS = ["-DSPDLOG_ACTIVE_LEVEL=1", "-O0", "-g"]
RELEASE_FLAGS = ["-O2"]
FAST_FLAGS = ["-O1"]

AES_COPT_FLAGS = select({
    "@platforms//cpu:aarch64": ["-O3"],
    "//conditions:default": [
        "-mavx",
        "-maes",
        "-mpclmul",
    ],
})

def _yacl_copts():
    return select({
        "@yacl//bazel:yacl_build_as_release": RELEASE_FLAGS,
        "@yacl//bazel:yacl_build_as_debug": DEBUG_FLAGS,
        "@yacl//bazel:yacl_build_as_fast": FAST_FLAGS,
        "//conditions:default": FAST_FLAGS,
    }) + WARNING_FLAGS

def yacl_cc_binary(
        copts = [],
        **kargs):
    cc_binary(
        copts = copts + _yacl_copts(),
        **kargs
    )

def yacl_cc_library(
        copts = [],
        deps = [],
        **kargs):
    cc_library(
        copts = _yacl_copts() + copts,
        deps = deps + [
            "@com_github_gabime_spdlog//:spdlog",
        ],
        **kargs
    )

def yacl_cmake_external(**attrs):
    if "generate_args" not in attrs:
        attrs["generate_args"] = ["-GNinja"]
    return cmake(**attrs)

def yacl_configure_make(**attrs):
    if "args" not in attrs:
        attrs["args"] = ["-j 8"]
    return configure_make(**attrs)

def yacl_cc_test(
        copts = [],
        deps = [],
        linkstatic = True,
        **kwargs):
    cc_test(
        copts = _yacl_copts() + copts,
        deps = deps + [
            "@com_google_googletest//:gtest_main",
        ],
        # static link for tcmalloc
        linkstatic = True,
        **kwargs
    )
