load("@yasl//bazel:yasl.bzl", "yasl_cmake_external")

package(default_visibility = ["//visibility:public"])

filegroup(
    name = "all_srcs",
    srcs = glob(["**"]),
)

yasl_cmake_external(
    name = "cpu_features",
    cache_entries = {
        "CMAKE_INSTALL_LIBDIR": "lib",
        "CMAKE_POSITION_INDEPENDENT_CODE": "ON",
        "BUILD_TESTING": "OFF",
    },
    lib_source = ":all_srcs",
    out_lib_dir = "lib",
    out_static_libs = ["libcpu_features.a"],
)
