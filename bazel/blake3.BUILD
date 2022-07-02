load("@rules_cc//cc:defs.bzl", "cc_library")

cc_library(
    name = "blake3_c",
    srcs = [
        "c/blake3.c",
        "c/blake3_dispatch.c",
        "c/blake3_portable.c",
    ] + select({
        "@bazel_tools//src/conditions:darwin_arm64": [
            "c/blake3_neon.c",
        ],
        "@bazel_tools//src/conditions:linux_aarch64": [
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
