#include <iostream>
#include "private_key.h"
#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/math/mpint/mp_int.h"
#include "ahesm2.h"
#include "config.h"

using yacl::crypto::EcGroupFactory;


int main() {
    // 参数配置并读取预计算表
    InitializeConfig();

    // 生成SM2椭圆曲线群
    auto ec_group = EcGroupFactory::Instance().Create("sm2", yacl::ArgLib = "openssl");
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
    auto c1 = Encrypt(m1,public_key);
    auto c2= Encrypt(m2,public_key);

    // 标量乘，即密文乘明文
    auto c3 = HMul(c1,m2,public_key);

    // 同态加，即密文加密文
    auto c4 = HAdd(c1,c2,public_key);

    // 单线程解密
    auto res3 = Decrypt(c3,private_key);

    // 并发解密
    auto res4 = ParDecrypt(c4,private_key);

    // 打印结果
    std::cout<<res3.m<<std::endl;
    std::cout<<res4.m<<std::endl;

    // 打印是否解密正确
    std::cout<<res3.success<<std::endl;
    std::cout<<res4.success<<std::endl;

    return 0;
}

