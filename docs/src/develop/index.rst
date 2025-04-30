Develop
=======

**For Traditioanl PKI:** Since there are so many existing time-proof, efficient, and standardized implementation of PKI algorithms, Yacl **does not re-implement** those algorithms. Instead, Yacl only provides a light-weighted and "easy-to-use" wrapper for the most popular industrial libraries (e.g. `OpenSSL <https://openssl.org/>`_, `TongSuo <https://github.com/Tongsuo-Project>`_, `LibSodium <https://doc.libsodium.org/>`_, etc.)

**For ECC (Elliptic-Curve Cryptography):** Yacl integrates many curve implementation from OpenSSL, MCL, LibSodium and other libraries, you may use the code in the following to use any curve as you like. For more information about all supported curve names, see: `yacl/crypto/ecc/curve_meta.cc <https://github.com/secretflow/yacl/blob/main/yacl/crypto/ecc/curve_meta.cc>`_

.. code-block:: cpp

   #include "yacl/crypto/ecc/ecc_spi.h"

   auto ec = yacl::crypto::EcGroupFactory::Instance().Create(
             /*** curve name */ "FourQ");

   auto order = ec->GetOrder();
   auto g = ec->GetGenerator();
   auto p = ec->GetField();

   // You can also:
   //     ec->Add(/* first point */, /* second point */);
   //     ec->Mul(/* first point */, /* second scalar */);
   //     ... for more see: yacl/crypto/ecc/ecc_spi.h

**For Hashing:** Yacl provides various hash functions, such as SHA256, SM3, Blake3, Shake256 and so on. You can use the code in the following to hash your data. For more information about all supported hash functions, see: `yacl/crypto/hash/hash_utils.cc <https://github.com/secretflow/yacl/blob/main/yacl/crypto/hash/hash_utils.cc>`_

.. code-block:: cpp

   #include "yacl/crypto/hash/hash_utils.h"

   auto sha256_hash = yacl::crypto::Sha256(/* your data */);
   auto sm3_hash = yacl::crypto::Sm3(/* your data */);

   // You can also use the following to hash your data
   // auto sha256_hash = yacl::crypto::SslHash(HashAlgorithm::SHA256).Update(/* your data */).CumulativeHash();
   // ... for more see: yacl/crypto/hash/hash_utils.h and yacl/crypto/hash/ssl_hash.h

**For Randomness** Yacl has also provide some easy-to-use randomness generation functions. Random functions usually start with **Secure** or **Fast**, secure random implementation uses the standardized ctr-drbg, and fast uses hash-drbg. It is always recommended to use **Secure**-Random functions.

.. code-block:: cpp

   #include "yacl/crypto/rand/rand.h"

   auto rand_u64 = yacl::crypto::SecureRandU64();
   auto rand_u128 = yacl::crypto::SecureRandU128();

   std::vector<uint8_t> rand_bytes = yacl::crypto::SecureRandBytes(10);

   // ... for more see: yacl/crypto/rand/rand.h

**For Secure Computation Protocols:** Yacl provides many secure computation primitives, such as OT, VOLE and so on. It is recommended to use the `yacl/kernel/...` api for general usage. For more advanced users, please use `yacl/algorithms/...`.

.. code-block:: cpp

   #include "yacl/kernel/ot_kernel.h"

   // ... setup link as lctx ..., at sender side
   OtSendStore ot_send(num_ot, OtStoreType::Compact);  // placeholder
   OtKernel kernel_send(OtKernel::Role::Sender, OtKernel::ExtAlgorithm::Ferret);
   kernel_send.init(lctx); // base ot
   kernel_send.eval_cot_random_choice(lctx, /* number of ot */, &ot_send);

   // ... setup link as lctx ..., at receiver side
   OtRecvStore ot_recv(num_ot, OtStoreType::Compact);  // placeholder
   OtKernel kernel_recv(OtKernel::Role::Receiver, OtKernel::ExtAlgorithm::Ferret);
   kernel_recv.init(lctx); // base ot
   kernel_recv.eval_cot_random_choice(lctx, /* number of ot */, &ot_recv);

**ECDH-PSI Example:** We also provide a step-to-step demo to demonstrate how to build an ECDH-PSI protocol from the tools that Yacl provides, and then bind the protocol implementation to JAVA and Python. See the following link for more detail.

.. toctree::
   :maxdepth: 1

   example_psi
   example_psi_java
   example_psi_python
