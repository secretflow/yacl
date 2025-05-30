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
echo -e "To ensure all dependencies are installed correctly, please run \033[32mbash ./run.sh\033[0m first."
echo -e "Please run \033[32mconda deactivate\033[0m to deactivate the conda environment and prevent Boost from being overridden."

mkdir BatchDualEx
cd BatchDualEx


git clone  --recursive https://github.com/osu-crypto/libOTe.git
cd libOTe
git reset --hard  e0727fe6dcfdd4
git submodule update --recursive
cp ../../libOte_cryptoTools.patch ./cryptoTools/
cd cryptoTools
git apply libOte_cryptoTools.patch
cd thirdparty/linux
bash all.get
cd ../../..  

cmake  -G "Unix Makefiles" -DBOOST_ROOT=cryptoTools/thirdparty/linux/boost   -DBoost_NO_SYSTEM_PATHS=ON   -DBoost_USE_STATIC_LIBS=ON
make

cd ..
# pwd
git clone https://github.com/osu-crypto/batchDualEx.git
cd ./batchDualEx
git checkout ffb7508342fc6d3e9288d6a79a74afbda0bd51d2
cp ../../batchDualEx_test.patch ./
git apply batchDualEx_test.patch
cd ./thirdparty/linux
bash ./ntl.get
cd ../..

cmake -G "Unix Makefiles"   -DBOOST_ROOT=../libOTe/cryptoTools/thirdparty/linux/boost   -DBoost_NO_SYSTEM_PATHS=ON   -DBoost_USE_STATIC_LIBS=ON
make

bash run_batchDualEx.sh

