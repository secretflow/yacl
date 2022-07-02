load("@yasl//bazel:yasl.bzl", "yasl_cmake_external")

package(default_visibility = ["//visibility:public"])

filegroup(
    name = "all_srcs",
    srcs = glob(["**"]),
)

yasl_cmake_external(
    name = "fmtlib",
    cache_entries = {
        "FMT_TEST": "OFF",
    },
    defines = ["FMT_HEADER_ONLY"],
    lib_source = ":all_srcs",
    out_headers_only = True,
)
