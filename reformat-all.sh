#!/bin/bash

find . -name '*.h' -o -name '*.cc' | xargs clang-format -i

buildifier -r .
