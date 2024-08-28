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

load("@yacl//bazel:yacl.bzl", "yacl_configure_make")

filegroup(
    name = "all_srcs",
    srcs = glob(
        include = ["**"],
        exclude = ["*.bazel"],
    ),
)

CONFIGURE_OPTIONS = [
    # fixed openssl work dir for deterministic build.
    "--openssldir=/tmp/openssl",
    "--libdir=lib",
    "no-legacy",
    "no-weak-ssl-ciphers",
    "no-tests",
    "no-shared",
    "no-ui-console",
    "enable-ntls",  # for GM
]

MAKE_TARGETS = [
    "build_programs",
    "install_sw",
]

yacl_configure_make(
    name = "tongsuo",
    args = ["-j 4"],
    configure_command = "Configure",
    configure_in_place = True,
    configure_options = CONFIGURE_OPTIONS,
    env = select({
        "@platforms//os:macos": {
            "AR": "",
        },
        "//conditions:default": {
            "MODULESDIR": "",
        },
    }),
    lib_name = "tongsuo",
    lib_source = ":all_srcs",
    linkopts = ["-ldl"],
    # Note that for Linux builds, libssl must come before libcrypto on the linker command-line.
    # As such, libssl must be listed before libcrypto
    out_static_libs = [
        "libssl.a",
        "libcrypto.a",
    ],
    targets = MAKE_TARGETS,
    visibility = ["//visibility:public"],
)
