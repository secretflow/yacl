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

load("@rules_foreign_cc//foreign_cc:defs.bzl", "make")

filegroup(
    name = "all_srcs",
    srcs = glob(["**"]),
)

config_setting(
    name = "linux_x64",
    constraint_values = [
        "@platforms//os:linux",
        "@platforms//cpu:x86_64",
    ],
)

config_setting(
    name = "linux_arm64",
    constraint_values = [
        "@platforms//os:linux",
        "@platforms//cpu:aarch64",
    ],
)

make(
    name = "FourQlib",
    args = ["-C FourQ_64bit_and_portable"],
    env = select({
        ":linux_x64": {"ARCH": "x64", "AVX": "TRUE", "AVX2": "FALSE"},
        ":linux_arm64": {"ARCH": "ARM64"},
        "@platforms//os:macos": {"ARCH": "x64", "GENERIC": "TRUE"}, # still work on macos M1
    }),
    defines = ["__LINUX__", "_ARM64_"],  # still work on macos and x64
    lib_source = ":all_srcs",
    out_static_libs = ["libFourQ.a"],
    targets = ["libFourQ", "install"],
    visibility = ["//visibility:public"],
)
