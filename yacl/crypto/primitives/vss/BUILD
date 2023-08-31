load("//bazel:yacl.bzl", "yacl_cc_library", "yacl_cc_test")

package(default_visibility = ["//visibility:public"])

yacl_cc_library(
    name = "poly",
    srcs = ["poly.cc"],
    hdrs = ["poly.h"],
    deps = [
        "//yacl/math/mpint",
    ],
)

yacl_cc_library(
    name = "vss",
    srcs = ["vss.cc"],
    hdrs = ["vss.h"],
    deps = [
        ":poly",
        "//yacl/crypto/base/ecc",
        "//yacl/math/mpint",
    ],
)

yacl_cc_test(
    name = "vss_test",
    srcs = ["vss_test.cc"],
    deps = [
        ":vss",
        ":poly",
        "//yacl/crypto/base/ecc",
        "//yacl/math/mpint",
    ],
)


