#!/bin/bash

OS_TYPE="$(uname)"

if [ "$OS_TYPE" == "Darwin" ]; then
    # macOS 系统
    brew list openssl || brew install openssl
    brew list pkg-config || brew install pkg-config
    brew list cmake || brew install cmake
elif [ "$OS_TYPE" == "Linux" ]; then
    if command -v apt-get >/dev/null; then
        # Ubuntu/Debian 系统
        sudo apt-get update
        sudo apt-get install -y software-properties-common
        sudo apt-get install -y cmake git build-essential libssl-dev pkg-config
    elif command -v yum >/dev/null; then
        # RHEL / CentOS / Fedora
        sudo yum install -y python3 gcc make git cmake gcc-c++ openssl-devel
    else
        echo "当前 Linux 发行版不受支持，请手动安装 cmake、git 和 libssl-dev"
        exit 1
    fi
else
    echo "当前系统 ($OS_TYPE) 不支持！"
    exit 1
fi

git clone https://github.com/emp-toolkit/emp-tool.git --branch master
cp ./communication_cost_tool.patch emp-tool/
cd emp-tool/
git apply --reject --whitespace=fix communication_cost_tool.patch
cmake .
make -j4
sudo make install
cd ..

wget https://raw.githubusercontent.com/emp-toolkit/emp-readme/master/scripts/install.py
python install_test.py --ot --sh2pc

cp ./communication_cost_sh2pc.patch emp-sh2pc/
cd emp-sh2pc
git apply --reject --whitespace=fix communication_cost_sh2pc.patch

mkdir build
cd build
cmake ..
make
cd ..

bash aes_run.sh
bash sha256_run.sh




