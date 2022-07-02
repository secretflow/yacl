workspace(name = "yasl")

load("//bazel:repositories.bzl", "yasl_deps")

yasl_deps()

load(
    "@rules_foreign_cc//foreign_cc:repositories.bzl",
    "rules_foreign_cc_dependencies",
)

rules_foreign_cc_dependencies(
    register_built_tools = False,
    register_default_tools = False,
    register_preinstalled_tools = True,
)

load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")

# Hedron's Compile Commands Extractor for Bazel
# https://github.com/hedronvision/bazel-compile-commands-extractor
git_repository(
    name = "hedron_compile_commands",
    commit = "1d21dc390e20ecb24d73e9dbb439e971e0d30337",
    remote = "https://gitee.com/anakin-xc/bazel-compile-commands-extractor.git",
    shallow_since = "1644967664 -0800",
)

load("@hedron_compile_commands//:workspace_setup.bzl", "hedron_compile_commands_setup")

hedron_compile_commands_setup()
