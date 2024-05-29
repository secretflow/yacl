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

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")

def yacl_deps():
    _rule_proto()
    _rule_python()
    _rules_foreign_cc()
    _com_github_madler_zlib()
    _com_google_protobuf()
    _com_github_gflags_gflags()
    _com_google_googletest()
    _com_google_absl()
    _com_github_google_leveldb()
    _com_github_brpc_brpc()
    _com_github_fmtlib_fmt()
    _com_github_gabime_spdlog()
    _com_github_google_benchmark()
    _com_github_google_cpu_features()
    _com_github_dltcollab_sse2neon()
    _com_github_msgpack_msgpack()
    _com_github_greendow_hash_drbg()

    # crypto related
    _com_github_openssl_openssl()
    _com_github_blake3team_blake3()
    _com_github_libsodium()
    _com_github_libtom_libtommath()
    _com_github_herumi_mcl()
    _com_github_microsoft_FourQlib()
    _lib25519()

    _simplest_ot()
    _org_interconnection()

def _simplest_ot():
    maybe(
        http_archive,
        name = "simplest_ot",
        urls = [
            "https://github.com/secretflow/simplest-ot/archive/4e39b7c35721c7fd968da6e047f59c0ac92e8088.tar.gz",
        ],
        strip_prefix = "simplest-ot-4e39b7c35721c7fd968da6e047f59c0ac92e8088",
        sha256 = "326e411c63b1cbd6697e9561a74f9d417df9394a988bf5c5e14775f14c612063",
    )

def _org_interconnection():
    maybe(
        http_archive,
        name = "org_interconnection",
        urls = [
            "https://github.com/secretflow/interconnection/archive/30e4220b7444d0bb077a9040f1b428632124e31a.tar.gz",
        ],
        strip_prefix = "interconnection-30e4220b7444d0bb077a9040f1b428632124e31a",
        sha256 = "341f6de0fa7dd618f9723009b9cb5b1da1788aacb9e12acfb0c9b19e5c5a7354",
    )

    # Add homebrew openmp for macOS, somehow..homebrew installs to different location on Apple Silcon/Intel macs.. so we need two rules here
    native.new_local_repository(
        name = "macos_omp_x64",
        build_file = "@yacl//bazel:local_openmp_macos.BUILD",
        path = "/usr/local/opt/libomp",
    )

    native.new_local_repository(
        name = "macos_omp_arm64",
        build_file = "@yacl//bazel:local_openmp_macos.BUILD",
        path = "/opt/homebrew/opt/libomp/",
    )

def _com_github_brpc_brpc():
    maybe(
        http_archive,
        name = "com_github_brpc_brpc",
        sha256 = "85856da0216773e1296834116f69f9e80007b7ff421db3be5c9d1890ecfaea74",
        strip_prefix = "brpc-1.9.0",
        type = "tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@yacl//bazel:patches/brpc.patch",
            "@yacl//bazel:patches/brpc_m1.patch",
        ],
        urls = [
            "https://github.com/apache/brpc/archive/refs/tags/1.9.0.tar.gz",
        ],
    )

def _com_github_gflags_gflags():
    maybe(
        http_archive,
        name = "com_github_gflags_gflags",
        strip_prefix = "gflags-2.2.2",
        sha256 = "34af2f15cf7367513b352bdcd2493ab14ce43692d2dcd9dfc499492966c64dcf",
        type = "tar.gz",
        urls = [
            "https://github.com/gflags/gflags/archive/v2.2.2.tar.gz",
        ],
    )

def _com_github_google_leveldb():
    maybe(
        http_archive,
        name = "com_github_google_leveldb",
        strip_prefix = "leveldb-1.23",
        sha256 = "9a37f8a6174f09bd622bc723b55881dc541cd50747cbd08831c2a82d620f6d76",
        type = "tar.gz",
        build_file = "@yacl//bazel:leveldb.BUILD",
        patch_args = ["-p1"],
        patches = ["@yacl//bazel:patches/leveldb.patch"],
        urls = [
            "https://github.com/google/leveldb/archive/refs/tags/1.23.tar.gz",
        ],
    )

def _com_github_madler_zlib():
    maybe(
        http_archive,
        name = "zlib",
        build_file = "@yacl//bazel:zlib.BUILD",
        strip_prefix = "zlib-1.3.1",
        sha256 = "17e88863f3600672ab49182f217281b6fc4d3c762bde361935e436a95214d05c",
        type = ".tar.gz",
        urls = [
            "https://github.com/madler/zlib/archive/refs/tags/v1.3.1.tar.gz",
        ],
    )

def _com_google_protobuf():
    maybe(
        http_archive,
        name = "com_google_protobuf",
        sha256 = "2c6a36c7b5a55accae063667ef3c55f2642e67476d96d355ff0acb13dbb47f09",
        strip_prefix = "protobuf-21.12",
        type = "tar.gz",
        patch_args = ["-p1"],
        patches = ["@yacl//bazel:patches/protobuf.patch"],
        urls = [
            "https://github.com/protocolbuffers/protobuf/releases/download/v21.12/protobuf-all-21.12.tar.gz",
        ],
    )

def _com_google_absl():
    maybe(
        http_archive,
        name = "com_google_absl",
        sha256 = "733726b8c3a6d39a4120d7e45ea8b41a434cdacde401cba500f14236c49b39dc",
        type = "tar.gz",
        strip_prefix = "abseil-cpp-20240116.2",
        urls = [
            "https://github.com/abseil/abseil-cpp/archive/refs/tags/20240116.2.tar.gz",
        ],
    )

def _com_github_openssl_openssl():
    maybe(
        http_archive,
        name = "com_github_openssl_openssl",
        sha256 = "9a7a7355f3d4b73f43b5730ce80371f9d1f97844ffc8c4b01c723ba0625d6aad",
        type = "tar.gz",
        strip_prefix = "openssl-openssl-3.0.12",
        urls = [
            "https://github.com/openssl/openssl/archive/refs/tags/openssl-3.0.12.tar.gz",
        ],
        build_file = "@yacl//bazel:openssl.BUILD",
    )

def _com_github_fmtlib_fmt():
    maybe(
        http_archive,
        name = "com_github_fmtlib_fmt",
        strip_prefix = "fmt-10.2.1",
        sha256 = "1250e4cc58bf06ee631567523f48848dc4596133e163f02615c97f78bab6c811",
        build_file = "@yacl//bazel:fmtlib.BUILD",
        urls = [
            "https://github.com/fmtlib/fmt/archive/refs/tags/10.2.1.tar.gz",
        ],
    )

def _com_github_gabime_spdlog():
    maybe(
        http_archive,
        name = "com_github_gabime_spdlog",
        strip_prefix = "spdlog-1.14.1",
        type = "tar.gz",
        sha256 = "1586508029a7d0670dfcb2d97575dcdc242d3868a259742b69f100801ab4e16b",
        build_file = "@yacl//bazel:spdlog.BUILD",
        urls = [
            "https://github.com/gabime/spdlog/archive/refs/tags/v1.14.1.tar.gz",
        ],
    )

def _com_google_googletest():
    maybe(
        http_archive,
        name = "com_google_googletest",
        sha256 = "8ad598c73ad796e0d8280b082cebd82a630d73e73cd3c70057938a6501bba5d7",
        type = "tar.gz",
        strip_prefix = "googletest-1.14.0",
        urls = [
            "https://github.com/google/googletest/archive/refs/tags/v1.14.0.tar.gz",
        ],
    )

def _com_github_google_benchmark():
    maybe(
        http_archive,
        name = "com_github_google_benchmark",
        type = "tar.gz",
        strip_prefix = "benchmark-1.8.4",
        sha256 = "3e7059b6b11fb1bbe28e33e02519398ca94c1818874ebed18e504dc6f709be45",
        urls = [
            "https://github.com/google/benchmark/archive/refs/tags/v1.8.4.tar.gz",
        ],
    )

def _com_github_blake3team_blake3():
    maybe(
        http_archive,
        name = "com_github_blake3team_blake3",
        strip_prefix = "BLAKE3-1.5.1",
        sha256 = "822cd37f70152e5985433d2c50c8f6b2ec83aaf11aa31be9fe71486a91744f37",
        build_file = "@yacl//bazel:blake3.BUILD",
        urls = [
            "https://github.com/BLAKE3-team/BLAKE3/archive/refs/tags/1.5.1.tar.gz",
        ],
    )

def _rule_proto():
    maybe(
        http_archive,
        name = "rules_proto",
        sha256 = "dc3fb206a2cb3441b485eb1e423165b231235a1ea9b031b4433cf7bc1fa460dd",
        strip_prefix = "rules_proto-5.3.0-21.7",
        urls = [
            "https://github.com/bazelbuild/rules_proto/archive/refs/tags/5.3.0-21.7.tar.gz",
        ],
    )

# Required by protobuf
def _rule_python():
    maybe(
        http_archive,
        name = "rules_python",
        sha256 = "4912ced70dc1a2a8e4b86cec233b192ca053e82bc72d877b98e126156e8f228d",
        strip_prefix = "rules_python-0.32.2",
        urls = [
            "https://github.com/bazelbuild/rules_python/archive/refs/tags/0.32.2.tar.gz",
        ],
    )

def _rules_foreign_cc():
    maybe(
        http_archive,
        name = "rules_foreign_cc",
        sha256 = "b3127e65fc189f28833be0cf64ba8b33b0bbb2707b7d448ba3baba5247a3c9f8",
        strip_prefix = "rules_foreign_cc-5c34b7136f0dec5d8abf2b840796ec8aef56a7c1",
        urls = [
            "https://github.com/bazelbuild/rules_foreign_cc/archive/5c34b7136f0dec5d8abf2b840796ec8aef56a7c1.tar.gz",
        ],
    )

def _com_github_libsodium():
    maybe(
        http_archive,
        name = "com_github_libsodium",
        type = "tar.gz",
        strip_prefix = "libsodium-1.0.18",
        sha256 = "6f504490b342a4f8a4c4a02fc9b866cbef8622d5df4e5452b46be121e46636c1",
        build_file = "@yacl//bazel:libsodium.BUILD",
        urls = [
            "https://github.com/jedisct1/libsodium/releases/download/1.0.18-RELEASE/libsodium-1.0.18.tar.gz",
        ],
    )

def _com_github_microsoft_FourQlib():
    maybe(
        http_archive,
        name = "com_github_microsoft_FourQlib",
        type = "tar.gz",
        strip_prefix = "FourQlib-1031567f23278e1135b35cc04e5d74c2ac88c029",
        sha256 = "7417c829d7933facda568c7a08924dfefb0c83dd1dab411e597af4c0cc0417f0",
        patch_args = ["-p1"],
        patches = [
            "@yacl//bazel:patches/FourQlib.patch",
        ],
        build_file = "@yacl//bazel:FourQlib.BUILD",
        urls = [
            "https://github.com/microsoft/FourQlib/archive/1031567f23278e1135b35cc04e5d74c2ac88c029.tar.gz",
        ],
    )

def _com_github_google_cpu_features():
    maybe(
        http_archive,
        name = "com_github_google_cpu_features",
        strip_prefix = "cpu_features-0.9.0",
        type = "tar.gz",
        build_file = "@yacl//bazel:cpu_features.BUILD",
        sha256 = "bdb3484de8297c49b59955c3b22dba834401bc2df984ef5cfc17acbe69c5018e",
        urls = [
            "https://github.com/google/cpu_features/archive/refs/tags/v0.9.0.tar.gz",
        ],
    )

def _com_github_dltcollab_sse2neon():
    maybe(
        http_archive,
        name = "com_github_dltcollab_sse2neon",
        sha256 = "787e0a7a64f1461b48232a7f9b9e9c14fa4a35a30875f2fb91aec6ddeaddfc0f",
        strip_prefix = "sse2neon-8df2f48dbd0674ae5087f7a6281af6f55fa5a8e2",
        type = "tar.gz",
        urls = [
            "https://github.com/DLTcollab/sse2neon/archive/8df2f48dbd0674ae5087f7a6281af6f55fa5a8e2.tar.gz",
        ],
        build_file = "@yacl//bazel:sse2neon.BUILD",
    )

def _com_github_libtom_libtommath():
    maybe(
        http_archive,
        name = "com_github_libtom_libtommath",
        sha256 = "7cfbdb64431129de4257e7d3349200fdbd4f229b470ff3417b30d0f39beed41f",
        type = "tar.gz",
        strip_prefix = "libtommath-42b3fb07e7d504f61a04c7fca12e996d76a25251",
        patch_args = ["-p1"],
        patches = [
            "@yacl//bazel:patches/libtommath.patch",
        ],
        urls = [
            "https://github.com/libtom/libtommath/archive/42b3fb07e7d504f61a04c7fca12e996d76a25251.tar.gz",
        ],
        build_file = "@yacl//bazel:libtommath.BUILD",
    )

def _com_github_msgpack_msgpack():
    maybe(
        http_archive,
        name = "com_github_msgpack_msgpack",
        type = "tar.gz",
        strip_prefix = "msgpack-c-cpp-6.1.0",
        sha256 = "5e63e4d9b12ab528fccf197f7e6908031039b1fc89cd8da0e97fbcbf5a6c6d3a",
        patches = [
            "@yacl//bazel:patches/msgpack.patch",
        ],
        patch_args = ["-p1"],
        urls = [
            "https://github.com/msgpack/msgpack-c/archive/refs/tags/cpp-6.1.0.tar.gz",
        ],
        build_file = "@yacl//bazel:msgpack.BUILD",
    )

def _com_github_greendow_hash_drbg():
    maybe(
        http_archive,
        name = "com_github_greendow_hash_drbg",
        sha256 = "c03a3da5742d0f0c40232817d84f21d8eed4c4af498c4dff3a51b3bcadcb3787",
        type = "tar.gz",
        strip_prefix = "Hash-DRBG-2411fa9d0de81c69dce2a48555c30298253db15d",
        urls = [
            "https://github.com/greendow/Hash-DRBG/archive/2411fa9d0de81c69dce2a48555c30298253db15d.tar.gz",
        ],
        build_file = "@yacl//bazel:hash_drbg.BUILD",
    )

def _com_github_herumi_mcl():
    maybe(
        http_archive,
        name = "com_github_herumi_mcl",
        strip_prefix = "mcl-1.88",
        sha256 = "7fcc630c008e973dda88dd1d1cd2bb14face95ee3ed3b2f717fbb25d340d6ba5",
        type = "tar.gz",
        build_file = "@yacl//bazel:mcl.BUILD",
        patch_args = ["-p1"],
        patches = [
            "@yacl//bazel:patches/mcl.patch",
        ],
        urls = ["https://github.com/herumi/mcl/archive/refs/tags/v1.88.tar.gz"],
    )

def _lib25519():
    maybe(
        http_archive,
        name = "lib25519",
        strip_prefix = "lib25519-20240321",
        sha256 = "d010baea719153fe3f012789b5a1de27d91fbbcfc65559e7eee5d802bf91eadd",
        type = "tar.gz",
        build_file = "@yacl//bazel:lib25519.BUILD",
        urls = [
            "https://lib25519.cr.yp.to/lib25519-20240321.tar.gz",
        ],
    )
