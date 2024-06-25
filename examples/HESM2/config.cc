// Completed by Guowei Ling

#include "config.h"
#include "t1.h"
#include "t2.h"

uint32_t GetSubBytesAsUint32(const yacl::Buffer& bytes, size_t start, size_t end) {
    uint32_t result = 0;
    for (size_t i = start; i < end; ++i) {
        result = (result << 8) | bytes.data<uint8_t>()[i];
    }
    return result;
}

int Ilen      = 12;   // l2-1
int Jlen      = 20;       // l1-1
int Imax      = 1<<Ilen; // 1<< Ilen
int Jmax      = 1<<Jlen; // 1<<Jlen
int L1      = Jmax*2; // 1<< Ilen
int L2      = Imax*2; // 1<< Ilen
int Treelen   = Imax*2; // imax*2
uint32_t Cuckoolen = static_cast<uint32_t>(Jmax * 1.3);
uint64_t Mmax = static_cast<uint64_t>(Imax)*static_cast<uint64_t>(L1)+Jmax;

CuckooT1 t1_loaded(Jmax,nullptr);
T2 t2_loaded(nullptr, false);

void InitializeConfig() {
    auto ec_group = yacl::crypto::EcGroupFactory::Instance().Create("sm2", yacl::ArgLib = "openssl");

    // 检查是否成功创建
    if (!ec_group) {
        std::cerr << "Failed to create SM2 curve using OpenSSL" << std::endl;
        return;
    }
    // 检查文件是否存在，如果存在则从文件加载
    std::string filet1 = "cuckoo_t1.dat";
    std::ifstream ifs(filet1);
    if (ifs.good()) {
        t1_loaded.Deserialize(filet1);
        SPDLOG_INFO("t1_loaded from file: {}",filet1);
    } else {
        SPDLOG_INFO("t1_loaded generated and serialized to file:{} ",filet1);
        SPDLOG_INFO("The process might be slow; you may need to wait a few minutes...");
        t1_loaded.InitializeEcGroup(std::move(ec_group));
        t1_loaded.Initialize();
        t1_loaded.Serialize(filet1);
    }

    auto ec_group_t2 = yacl::crypto::EcGroupFactory::Instance().Create("sm2", yacl::ArgLib = "openssl");
    std::string filet2 = "t2.dat";
    std::ifstream ifst2(filet2);
    if (ifst2.good()) {
        t2_loaded.Deserialize(filet2);
        SPDLOG_INFO("t2_loaded from file: {}",filet2);
    } else {
        SPDLOG_INFO("t2_loaded generated and serialized to file:{} ",filet2);
        t2_loaded.InitializeEcGroup(std::move(ec_group_t2));
        t2_loaded.InitializeVector();
        t2_loaded.Serialize(filet2);
        t2_loaded.Deserialize(filet2);
        
    }

}



