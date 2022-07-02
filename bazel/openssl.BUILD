load("@rules_foreign_cc//foreign_cc:defs.bzl", "configure_make")

package(default_visibility = ["//visibility:public"])

filegroup(
    name = "all_srcs",
    srcs = glob(["**"]),
)

configure_make(
    name = "openssl",
    configure_command = "config",
    configure_options = [
        # fixed openssl work dir for deterministic build.
        "--openssldir=/tmp/openssl",
        "no-shared",
        # https://www.openssl.org/docs/man1.1.0/man3/OpenSSL_version.html
        # OPENSSL_ENGINES_DIR point to /tmp path randomly generated.
        "no-engine",
        "no-tests",
    ],
    env = select({
        "@bazel_tools//src/conditions:darwin": {
            "AR": "",
        },
        "//conditions:default": {},
    }),
    lib_source = ":all_srcs",
    out_static_libs = [
        "libssl.a",
        "libcrypto.a",
    ],
    targets = [
        # NOTE: $(nproc --all) returns host number of cpus in ANT ACI pod
        # Hence we choose a fixed number of 4.
        # "make -j`nproc --all`",
        "-s -j4",
        "-s install_sw",
    ],
)
