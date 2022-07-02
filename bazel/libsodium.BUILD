load("@yasl//bazel:yasl.bzl", "yasl_configure_make")

package(default_visibility = ["//visibility:public"])

filegroup(
    name = "all_srcs",
    srcs = glob(["**"]),
)

yasl_configure_make(
    name = "libsodium",
    env = {
        "AR": "",
    },
    lib_source = ":all_srcs",
    out_static_libs = ["libsodium.a"],
    targets = ["install"],
)
