# Copyright 2024 Ant Group Co., Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

load("@yacl//bazel:yacl.bzl", "yacl_cmake_external")

package(default_visibility = ["//visibility:public"])

filegroup(
    name = "source",
    srcs = glob(["**"]),
)

# This is the value could be defined by --config=android_arm64
config_setting(
    name = "cpu_arm64_v8a",
    values = {"cpu": "arm64-v8a"},
    visibility = ["//visibility:private"],
)

default_config = {
    "MCL_BUILD_TESTING": "OFF",
    # remove dependency on libgmp
    "MCL_TEST_WITH_GMP": "OFF",
    "MCL_STATIC_LIB": "ON",
}

android_config = {
    "MCL_BUILD_TESTING": "OFF",
    # remove dependency on libgmp
    "MCL_TEST_WITH_GMP": "OFF",
    "MCL_STATIC_LIB": "ON",
    "MCL_USE_LLVM": "OFF",
    "CMAKE_SYSTEM_NAME": "Android",
    "CMAKE_ANDROID_NDK": "$ANDROID_NDK_HOME",
    "CMAKE_ANDROID_ARCH_ABI": "arm64-v8a",
}

yacl_cmake_external(
    name = "mcl",
    build_args = ["-j"],
    cache_entries = select({
        ":cpu_arm64_v8a": android_config,
        "//conditions:default": default_config,
    }),
    # generate_crosstool_file = False,
    lib_source = ":source",
    out_static_libs = [
        "libmcl.a",
    ],
    alwayslink = True,
)
