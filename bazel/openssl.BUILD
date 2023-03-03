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

load("@rules_foreign_cc//foreign_cc:defs.bzl", "configure_make")

package(default_visibility = ["//visibility:public"])

filegroup(
    name = "all_srcs",
    srcs = glob(["**"]),
)

configure_make(
    name = "openssl",
    configure_command = "config",
    configure_options = [
        # fixed openssl work dir for deterministic build.
        "--openssldir=/tmp/openssl",
        "no-shared",
        # https://www.openssl.org/docs/man1.1.0/man3/OpenSSL_version.html
        # OPENSSL_ENGINES_DIR point to /tmp path randomly generated.
        "no-engine",
        "no-tests",
    ],
    env = select({
        "@bazel_tools//src/conditions:darwin": {
            "AR": "",
        },
        "//conditions:default": {},
    }),
    lib_source = ":all_srcs",
    linkopts = ["-ldl"],
    out_static_libs = [
        "libssl.a",
        "libcrypto.a",
    ],
    targets = [
        # NOTE: $(nproc --all) returns host number of cpus in ANT ACI pod
        # Hence we choose a fixed number of 4.
        # "make -j`nproc --all`",
        "-s -j4",
        "-s install_sw",
    ],
)
