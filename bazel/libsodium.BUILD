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

genrule(
    name = "gen_sh",
    outs = ["gen.sh"],
    cmd = """
cat > $@ <<"EOF"
#!/bin/sh
sed -e 's/@VERSION@/1.0.18/g' \
    -e 's/@SODIUM_LIBRARY_VERSION_MAJOR@/11/g' \
    -e 's/@SODIUM_LIBRARY_VERSION_MINOR@/0/g' \
    -e 's/@SODIUM_LIBRARY_MINIMAL_DEF@//g'
EOF""",
)

genrule(
    name = "version_h",
    srcs = ["src/libsodium/include/sodium/version.h.in"],
    outs = ["src/libsodium/include/sodium/version.h"],
    cmd = "$(location :gen_sh) < $(<) > $(@)",
    tools = [":gen_sh"],
)

cc_library(
    name = "libsodium",
    srcs = glob(
        include = ["src/**/*.c"],
    ) + [":version_h"],
    hdrs = glob(["src/**/*.h"] + [":version_h"]),
    copts = [
        "-DCONFIGURED",
        "-DHAVE_TI_MODE",
    ],
    includes = [
        "src/libsodium/crypto_core/curve25519/ref10",
        "src/libsodium/crypto_generichash/blake2b/ref",
        "src/libsodium/crypto_onetimeauth/poly1305",
        "src/libsodium/crypto_onetimeauth/poly1305/donna",
        "src/libsodium/crypto_onetimeauth/poly1305/sse2",
        "src/libsodium/crypto_pwhash/argon2",
        "src/libsodium/crypto_pwhash/scryptsalsa208sha256",
        "src/libsodium/crypto_scalarmult/curve25519",
        "src/libsodium/crypto_scalarmult/curve25519/donna_c64",
        "src/libsodium/crypto_scalarmult/curve25519/ref10",
        "src/libsodium/crypto_scalarmult/curve25519/sandy2x",
        "src/libsodium/crypto_shorthash/siphash24/ref",
        "src/libsodium/crypto_sign/ed25519/ref10",
        "src/libsodium/crypto_stream/chacha20",
        "src/libsodium/crypto_stream/chacha20/dolbeau",
        "src/libsodium/crypto_stream/chacha20/ref",
        "src/libsodium/crypto_stream/salsa20",
        "src/libsodium/crypto_stream/salsa20/ref",
        "src/libsodium/crypto_stream/salsa20/xmm6",
        "src/libsodium/crypto_stream/salsa20/xmm6int",
        "src/libsodium/include",
        "src/libsodium/include/sodium",
        "src/libsodium/include/sodium/private",
    ],
    visibility = ["//visibility:public"],
)
