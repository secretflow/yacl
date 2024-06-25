// Completed by Guowei Ling

#ifndef CIPHERTEXT_H_
#define CIPHERTEXT_H_

#include <utility>

#include "yacl/crypto/ecc/ec_point.h"

class Ciphertext {
public:
    Ciphertext(yacl::crypto::EcPoint  c1, yacl::crypto::EcPoint  c2)
        : c1_(std::move(c1)), c2_(std::move(c2)) {}

    const yacl::crypto::EcPoint& GetC1() const { return c1_; }
    const yacl::crypto::EcPoint& GetC2() const { return c2_; }

private:
    yacl::crypto::EcPoint c1_;
    yacl::crypto::EcPoint c2_;
};

#endif  // CIPHERTEXT_H_

