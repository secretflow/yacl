# CUDA SM2 Backend

This directory contains an **opt-in** CUDA-backed SM2 implementation (`CUDA_SM2`)
for YACL's `EcGroup` SPI.

## Build / Test / Benchmark

Note: all targets under `//yacl/crypto/ecc/cuda:*` are tagged as `manual`, so they
won't be included by wildcard patterns unless explicitly specified.

- Unit test:
  - `bazel test //yacl/crypto/ecc/cuda:cuda_sm2_test -c opt --test_output=errors`
- Benchmark:
  - `CUDA_VISIBLE_DEVICES=0 bazel run //yacl/crypto/ecc/cuda:bench_cuda_sm2 -c opt -- --benchmark_filter=Sm2BenchmarkFixture/.*`

## Local test results

**Commit:** `37100247fb75edfc3e40e7b94564e333ca4e248d`  

**Machine:**
- OS: Ubuntu 20.04.1 (kernel `5.4.0-113-generic`)
- CPU: Intel Xeon Gold 6226R @ 2.90GHz (2 sockets, 32C/64T)
- GPU (selected): NVIDIA GeForce RTX 3090 (24GB) (`CUDA_VISIBLE_DEVICES=0`)
- Driver: 580.119.02 (`nvidia-smi` reports CUDA Version 13.0)
- CUDA toolkit: nvcc 12.8 (`Cuda compilation tools, release 12.8, V12.8.61`)

### Tests

- `bazel test //yacl/... -c opt`: **PASSED** (122 tests)
- `bazel test //yacl/crypto/ecc/cuda:cuda_sm2_test -c opt`: **PASSED**

### Performance (Google Benchmark)

Command:
- `CUDA_VISIBLE_DEVICES=0 bazel run //yacl/crypto/ecc/cuda:bench_cuda_sm2 -c opt -- --benchmark_min_time=0.2s --benchmark_filter='Sm2BenchmarkFixture/(CPU_MulBase$|CPU_BatchMul/100000$|GPU_BatchMulBase/100000$|GPU_BatchMulBase_Large/1000000$|GPU_BatchMul/100000$|PSI_CPU_HashAndMul/100000$|PSI_GPU_HashAndMul/100000$)'`

Results (higher is better):

| Operation (batch size) | CPU (OpenSSL) | GPU (CUDA_SM2) | Speedup |
|---|---:|---:|---:|
| `MulBase` vs `BatchMulBase` (100000) | 3.012 k items/s | 1.666 M items/s | **553×** |
| `Mul` batch (100000) | 3.016 k items/s | 126.821 k items/s | **42.0×** |
| `HashToCurve+Mul` batch (100000) | 2.709 k items/s | 752.310 k items/s | **277.7×** |
| `BatchMulBase` large (1000000) | N/A | 1.593 M items/s | N/A |

### GPU utilization (nvidia-smi dmon)

Measured during:
- `CUDA_VISIBLE_DEVICES=0 bazel run //yacl/crypto/ecc/cuda:bench_cuda_sm2 -c opt -- --benchmark_min_time=10s --benchmark_filter='Sm2BenchmarkFixture/GPU_BatchMulBase_Large/1000000'`

Sampling tool:
- `nvidia-smi dmon -i 0 -s pum -d 1`

Observed on GPU0 (sampling is coarse; reported as **active samples** where SM% > 0):
- SM utilization: avg **56.3%**, peak **87%**
- GPU memory used (FB): **367 MiB** (stable during the run)
- Power draw: avg **146 W**, peak **153 W**
- GPU temp: avg **38.8°C**, peak **41°C**

