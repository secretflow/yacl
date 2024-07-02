# 加法同态SM2+FastECDLP

本代码是SM2加法同态加密 ([密码学报 2022](http://www.jcr.cacrnet.org.cn/CN/10.13868/j.cnki.jcr.000532)) 结合FastECDLP([IEEE TIFS 2023](https://ieeexplore.ieee.org/document/10145804))。

注：本实现的SM2加法同态加密并非是标准SM2公钥加密算法。标准SM2公钥加密算法并不具备加同态性。

## 快速开始

首先，进入项目目录并构建示例：

```bash
cd yacl

bazel build --linkopt=-ldl //...

bazel build --linkopt=-ldl //examples/hesm2:sm2_example

cd bazel-bin/examples/hesm2

./sm2_example
```

**注：** 第一次使用需要生成预计算表，请等待几分钟。

## 示例代码

以下是一个简单的使用示例，展示了如何进行参数配置、加密、同态运算及解密操作。

```cpp
#include <iostream>

#include "examples/hesm2/ahesm2.h"
#include "examples/hesm2/config.h"
#include "examples/hesm2/private_key.h"

#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/math/mpint/mp_int.h"

using yacl::crypto::EcGroupFactory;
using namespace examples::hesm2;

int main() {
  // 参数配置并读取预计算表
  InitializeConfig();

  // 生成SM2椭圆曲线群
  auto ec_group =
      EcGroupFactory::Instance().Create("sm2", yacl::ArgLib = "openssl");
  if (!ec_group) {
    std::cerr << "Failed to create SM2 curve using OpenSSL" << std::endl;
    return 1;
  }

  // 公私钥对生成
  PrivateKey private_key(std::move(ec_group));
  const auto& public_key = private_key.GetPublicKey();

  // 指定明文
  auto m1 = yacl::math::MPInt(100);
  auto m2 = yacl::math::MPInt(6);

  // 加密
  auto c1 = Encrypt(m1, public_key);
  auto c2 = Encrypt(m2, public_key);

  // 标量乘，即密文乘明文
  auto c3 = HMul(c1, m2, public_key);

  // 同态加，即密文加密文
  auto c4 = HAdd(c1, c2, public_key);

  // 单线程解密
  auto res3 = Decrypt(c3, private_key);

  // 并发解密
  auto res4 = ParDecrypt(c4, private_key);

  // 打印结果
  std::cout << res3.m << std::endl;
  std::cout << res4.m << std::endl;

  // 打印是否解密正确
  std::cout << res3.success << std::endl;
  std::cout << res4.success << std::endl;

  return 0;
}
```

## 高阶使用

您可以通过修改config.cc中的以下两个参数修改明文空间。

```cpp
int Ilen      = 12;   // l2-1
int Jlen      = 20;       // l1-1
```

明文空间的绝对值大小为：(1<<Ilen)*(1<<(1+Jlen))+(1<<Jlen)。因此，本实现的默认明文空间为：[-8590983168,8590983168]。如果您需要更大的明文空间，请直接修改。另外，注意需要删除掉在bazel-bin/examples/HESM2/目录下的cuckoo_t1.dat和t2.dat（该实现会自动帮您重新生成预计算表）。
