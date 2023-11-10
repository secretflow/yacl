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

load("@yacl//bazel:yacl.bzl", "yacl_configure_make")

package(default_visibility = ["//visibility:public"])

filegroup(
    name = "all_srcs",
    srcs = glob(["**"]),
)

# This is the value defined by --config=android_arm64
config_setting(
    name = "cpu_arm64_v8a",
    values = {"cpu": "arm64-v8a"},
    visibility = ["//visibility:private"],
)

yacl_configure_make(
    name = "openssl",
    configure_command = select(
        {
            ":cpu_arm64_v8a": "Configure",  # Use Configure for android build
            "//conditions:default": "config",
        },
    ),
    configure_options = [
        # fixed openssl work dir for deterministic build.
        "--openssldir=/tmp/openssl",
        "--libdir=lib",
        "no-shared",
        # https://www.openssl.org/docs/man1.1.0/man3/OpenSSL_version.html
        # OPENSSL_ENGINES_DIR point to /tmp path randomly generated.
        "no-engine",
        "no-tests",
    ] + select(
        {
            ":cpu_arm64_v8a": ["android-arm64"],
            "//conditions:default": [],
        },
    ),
    copts = ["-Wno-format"],
    env = select({
        "@bazel_tools//src/conditions:darwin": {
            "ARFLAGS": "-static -s -o",
        },
        "//conditions:default": {
        },
    }),
    lib_source = ":all_srcs",
    linkopts = ["-ldl"],
    out_static_libs = [
        "libssl.a",
        "libcrypto.a",
    ],
    targets = [
        "-s",
        "-s install_sw",
    ],
)
