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

load("@rules_cc//cc:defs.bzl", "cc_library")

cc_library(
    name = "blake3_c",
    srcs = [
        "c/blake3.c",
        "c/blake3_dispatch.c",
        "c/blake3_portable.c",
    ] + select({
        "@platforms//cpu:aarch64": [
            "c/blake3_neon.c",
        ],
        "//conditions:default": [
            "c/blake3_sse2_x86-64_unix.S",
            "c/blake3_sse41_x86-64_unix.S",
            "c/blake3_avx2_x86-64_unix.S",
            "c/blake3_avx512_x86-64_unix.S",
        ],
    }),
    hdrs = [
        "c/blake3.h",
        "c/blake3_impl.h",
    ],
    defines = ["BLAKE3_C_EXTERNAL"],
    includes = ["include"],
    visibility = ["//visibility:public"],
)
