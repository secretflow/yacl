load("@yasl//bazel:yasl.bzl", "yasl_cmake_external")

package(default_visibility = ["//visibility:public"])

filegroup(
    name = "all_srcs",
    srcs = glob(["**"]),
)

yasl_cmake_external(
    name = "spdlog",
    cache_entries = {
        "SPDLOG_BUILD_EXAMPLE": "OFF",
        "SPDLOG_FMT_EXTERNAL": "ON",
        "SPDLOG_NO_TLS": "ON",
        "CMAKE_INSTALL_LIBDIR": "lib",
    },
    defines = [
        "SPDLOG_FMT_EXTERNAL",
        "SPDLOG_NO_TLS",
    ],
    lib_source = ":all_srcs",
    out_lib_dir = "lib",
    out_static_libs = select({
        "@yasl//bazel:yasl_build_as_debug": ["libspdlogd.a"],
        "//conditions:default": ["libspdlog.a"],
    }),
    deps = [
        "@com_github_fmtlib_fmt//:fmtlib",
    ],
)
