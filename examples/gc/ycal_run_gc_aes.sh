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
cd ../..
bazel build examples/gc:aes_run
bazel-bin/examples/gc/aes_run > examples/gc/outputs_tmp.txt
total_garbler_send=0
total_evaluator_send=0
total_time=0

# 总次数
total=100

# 清空旧输出
> examples/gc/outputs_tmp.txt
echo "=========================== AES Epoch 100 Batch 1 =================================="
# 运行 100 次
for ((i=1; i<=total; i++)); do
  output=$(bazel-bin/examples/gc/aes_run)
  echo "$output" >> examples/gc/outputs_tmp.txt

  # 提取信息
  garbler_bytes=$(echo "$output" | grep "Garbler send" | awk '{print $3}')
  evaluator_bytes=$(echo "$output" | grep "Evaluator send" | awk '{print $3}')
  time_us=$(echo "$output" | grep "Time for Computing" | awk '{print $4}' | sed 's/us//')

  # 累加
  total_garbler_send=$((total_garbler_send + garbler_bytes))
  total_evaluator_send=$((total_evaluator_send + evaluator_bytes))
  total_time=$((total_time + time_us))

  # 进度条
  progress=$((i * 100 / total))
  echo -ne "Running [$i/$total] ["
  for ((j=0; j<progress/2; j++)); do echo -n "#"; done
  for ((j=progress/2; j<50; j++)); do echo -n "."; done
  echo -ne "] $progress% \r"
done

# 换行
echo

# 输出统计
echo "Total Garbler send: $((total_garbler_send / 1024)) KB"
echo "Total Evaluator send: $((total_evaluator_send / 1024)) KB"
echo "Total Time for Computing: ${total_time} us"

# 输出到文件
echo "Total Garbler send: $((total_garbler_send / 1024)) KB" > examples/gc/aes_summary.txt
echo "Total Evaluator send: $((total_evaluator_send / 1024)) KB" >> examples/gc/aes_summary.txt
echo "Total Time for Computing: ${total_time} us" >> examples/gc/aes_summary.txt



rm examples/gc/outputs_tmp.txt