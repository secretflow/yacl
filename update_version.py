#! /usr/bin/env python3

# Copyright 2024 Ant Group Co., Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse
import re

def update_first_matched_version_in_file(file_path, new_version):
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()
        version_pattern = r'version = "[^"]*"';
        new_content = re.sub(version_pattern, f'version = "{new_version}"', content, count = 1)

        with open(file_path, 'w', encoding="utf-8") as f:
            f.write(new_content)

def main():
    parser = argparse.ArgumentParser(description="Update YACL release version")

    parser.add_argument(
        "--version",
        metavar="bazel module version",
        type=str,
        help="bazel module version",
        required=True,
    )

    args = parser.parse_args()

    update_first_matched_version_in_file("MODULE.bazel", args.version)



if __name__ == "__main__":
    main()
