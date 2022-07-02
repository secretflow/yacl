load("@yasl//bazel:yasl.bzl", "yasl_cmake_external")

package(default_visibility = ["//visibility:public"])

filegroup(
    name = "all_srcs",
    srcs = glob(["**"]),
)

yasl_cmake_external(
    name = "emp-tool",
    cache_entries = {
        "OPENSSL_ROOT_DIR": "$EXT_BUILD_DEPS/openssl",
        "BUILD_TESTING": "OFF",
    },
    lib_source = ":all_srcs",
    out_data_dirs = ["cmake"],
    out_static_libs = [
        "libemp-tool.a",
    ],
    deps = [
        "@com_github_openssl_openssl//:openssl",
    ],
)
