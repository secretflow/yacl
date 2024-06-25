// Completed by Guowei Ling

#ifndef T2_H_
#define T2_H_

#include <utility>
#include <vector>
#include <memory>
#include <fstream>
#include <shared_mutex>
#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/math/mpint/mp_int.h"
#include "config.h"  

class T2 {
public:
    explicit T2(std::shared_ptr<yacl::crypto::EcGroup> ec_group, bool initialize = true)
        : ec_group_(std::move(ec_group)) {
        if (initialize) {
            InitializeVector();
        }
    }
    const yacl::crypto::AffinePoint& GetValue(size_t index) const {
        return vec_.at(index);
    }
    const std::vector<yacl::crypto::AffinePoint>& GetVector() const {
        return vec_;
    }
    void Serialize(const std::string& filename) const {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        std::ofstream ofs(filename, std::ios::binary);
        if (!ofs) {
            throw std::runtime_error("Failed to open file for writing: " + filename);
        }
        size_t vec_size = vec_.size();
        ofs.write(reinterpret_cast<const char*>(&vec_size), sizeof(vec_size));
        for (const auto& point : vec_) {
            auto x_bytes = point.x.ToMagBytes(yacl::Endian::native);
            auto y_bytes = point.y.ToMagBytes(yacl::Endian::native);
            size_t x_size = x_bytes.size();
            size_t y_size = y_bytes.size();
            ofs.write(reinterpret_cast<const char*>(&x_size), sizeof(x_size));
            ofs.write(reinterpret_cast<const char*>(x_bytes.data<uint8_t>()), x_size);
            ofs.write(reinterpret_cast<const char*>(&y_size), sizeof(y_size));
            ofs.write(reinterpret_cast<const char*>(y_bytes.data<uint8_t>()), y_size);
        }
    }
    void Deserialize(const std::string& filename) {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        std::ifstream ifs(filename, std::ios::binary);
        if (!ifs) {
            throw std::runtime_error("Failed to open file for reading: " + filename);
        }
        size_t vec_size;
        ifs.read(reinterpret_cast<char*>(&vec_size), sizeof(vec_size));
        vec_.resize(vec_size);
        for (size_t i = 0; i < vec_size; ++i) {
            size_t x_size;
            size_t y_size;
            ifs.read(reinterpret_cast<char*>(&x_size), sizeof(x_size));
            yacl::Buffer x_bytes(x_size);
            ifs.read(reinterpret_cast<char*>(x_bytes.data<uint8_t>()), x_size);
            yacl::math::MPInt x;
            x.FromMagBytes(x_bytes, yacl::Endian::native);

            ifs.read(reinterpret_cast<char*>(&y_size), sizeof(y_size));
            yacl::Buffer y_bytes(y_size);
            ifs.read(reinterpret_cast<char*>(y_bytes.data<uint8_t>()), y_size);
            yacl::math::MPInt y;
            y.FromMagBytes(y_bytes, yacl::Endian::native);

            vec_[i] = yacl::crypto::AffinePoint{x, y};
        }
    }

    void InitializeVector() {
        vec_.resize(Imax+1);  // 预先分配内存
        auto G = ec_group_->GetGenerator();
        yacl::math::MPInt Jmax_val(Jmax);
        yacl::math::MPInt two(2);
        yacl::math::MPInt factor = Jmax_val * two; // Correcting the multiplication
        auto T2basepoint = ec_group_->MulBase(factor);
        for (int i = 0; i <= Imax; ++i) {
            yacl::math::MPInt value(-i);
            auto point = ec_group_->Mul(T2basepoint, value);
            vec_[i] = ec_group_->GetAffinePoint(point);  // 直接赋值到指定位置
        }
    }

    void InitializeEcGroup(std::shared_ptr<yacl::crypto::EcGroup> ec_group) {
        ec_group_ = std::move(ec_group);
    }

private:
    std::shared_ptr<yacl::crypto::EcGroup> ec_group_;
    std::vector<yacl::crypto::AffinePoint> vec_;
    mutable std::shared_mutex mutex_;
};

extern T2 t2_loaded;

#endif  // T2_H_
