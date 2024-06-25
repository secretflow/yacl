// Completed by Guowei Ling

#include "ciphertext.h"
#include "private_key.h"

struct DecryptResult {
    yacl::math::MPInt m;
    bool success;
};

Ciphertext Encrypt(const yacl::math::MPInt& message, const PublicKey& pk);

DecryptResult Decrypt(const Ciphertext& ciphertext, const PrivateKey& sk);

DecryptResult ParDecrypt(const Ciphertext& ciphertext, const PrivateKey& sk);

Ciphertext HAdd(const Ciphertext& ciphertext1, const Ciphertext& ciphertext2,const PublicKey& pk);

Ciphertext HSub(const Ciphertext& ciphertext1, const Ciphertext& ciphertext2,const PublicKey& pk);

Ciphertext HMul(const Ciphertext& ciphertext1, const yacl::math::MPInt& scalar,const PublicKey& pk);



