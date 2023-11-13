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

load("@yacl//bazel:yacl.bzl", "yacl_cmake_external")

package(default_visibility = ["//visibility:public"])

filegroup(
    name = "all_srcs",
    srcs = glob(["**"]),
)

yacl_cmake_external(
    name = "msgpack",
    cache_entries = {
        "MSGPACK_CXX17": "ON",
        "MSGPACK_USE_BOOST": "OFF",
        "MSGPACK_BUILD_EXAMPLES": "OFF",
        "BUILD_SHARED_LIBS": "OFF",
        "MSGPACK_BUILD_TESTS": "OFF",
    },
    defines = ["MSGPACK_NO_BOOST"],
    lib_source = ":all_srcs",
    out_headers_only = True,
)
