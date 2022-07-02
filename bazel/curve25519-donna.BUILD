load("@rules_cc//cc:defs.bzl", "cc_library")

cc_library(
    name = "curve25519_donna",
    srcs = ["curve25519.c"],
    hdrs = glob(["*.h"]),
    visibility = ["//visibility:public"],
)
