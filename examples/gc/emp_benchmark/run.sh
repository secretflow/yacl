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




