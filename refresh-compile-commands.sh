#!/bin/bash
cd "${0%/*}"
rm -rf ./external
rm -f compile_commands.json

ln -s bazel-out/../../../external .
bazel run @hedron_compile_commands//:refresh_all
