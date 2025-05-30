#!/bin/bash
#
# Copyright 2025 Ant Group Co., Ltd.
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
#
set -e

echo -e "Please run \033[32mconda deactivate\033[0m to deactivate the conda environment and prevent Boost from being overridden."
sleep 1

OS_TYPE="$(uname)"

if [ "$OS_TYPE" == "Darwin" ]; then
    # macOS 系统
    brew list openssl || brew install openssl
    brew list pkg-config || brew install pkg-config
    brew list cmake || brew install cmake
    brew list boost || brew install boost
    brew list gmp || brew install gmp

elif [ "$OS_TYPE" == "Linux" ]; then
    if command -v apt-get >/dev/null; then
        # Ubuntu/Debian 系统
        sudo apt-get update
        sudo apt-get install -y software-properties-common
        sudo apt-get install -y \
            cmake \
            git \
            build-essential \
            libssl-dev \
            pkg-config \
            libgmp-dev \
            libboost-all-dev

    elif command -v yum >/dev/null; then
        # RHEL / CentOS / Fedora
        sudo yum install -y \
            python3 \
            gcc \
            make \
            git \
            cmake \
            gcc-c++ \
            openssl-devel \
            gmp-devel \
            boost-devel

    else
        echo "The current Linux distribution is not supported. Please manually install cmake, git, libssl-dev, libgmp-dev, and libboost."
        exit 1
    fi
else
    echo "The current system ($OS_TYPE) is not supported!"
    exit 1
fi

mkdir emp_toolkit
cd emp_toolkit
git clone https://github.com/emp-toolkit/emp-tool.git
cp ../communication_cost_tool.patch emp-tool/
cd emp-tool/
git checkout 8052d95ddf56b519a671b774865bb13157b3b4e0
git apply communication_cost_tool.patch
cmake .
make -j4
sudo make install
cd ..

git clone https://github.com/emp-toolkit/emp-readme.git
cp ../emp-readme-install.patch emp-readme/
cd emp-readme/
git checkout 28ed3ab07be2edda6d7841692be2c552d22d7cf5
git apply emp-readme-install.patch
cp scripts/install.py ../
cd ..

python install.py --ot --sh2pc
cd ..

git clone https://github.com/emp-toolkit/emp-sh2pc.git
cp ./communication_cost_sh2pc.patch emp-sh2pc
cd emp-sh2pc
git checkout 61589f52111a26015b2bb8ab359dc457f8a246eb
git apply --reject --whitespace=fix communication_cost_sh2pc.patch

mkdir build
cd build
cmake ..
make -j4
cd ..

bash aes_run.sh
bash sha256_run.sh
cd ..
echo "ABY Test"

git clone https://github.com/encryptogroup/ABY.git
cd ABY
git checkout d8e69414d091cafc007e65a03ef30768ebaf723d
cp ../ABY_aes_test.patch ./
git apply ABY_aes_test.patch
mkdir build
cd build
cmake .. -DABY_BUILD_EXE=On
make
cd ..
bash run_aes.sh