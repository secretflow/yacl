Research
========

Yacl is also designed for cryptography researchers. We notice that junior (or early-career) cryptography researchers have been constantly finding it difficult to demonstrate their new ideas, or run emperical benchmarks.

Desite the **ECC, Random, and Secure Computation** introduced in `Develop Section <../develop/index.html>`_. Yacl has provided the following tools for cryptographic researchers.

.. note::

   Yacl has dedicated to long-term support for cryptography research, please do not hesitation to contact us for security issues, bugs, pull requests, or requiring new features .

**yacl/math:** Yacl provides ``MPInt`` type for big number operations.

.. code-block:: cpp

   #include "yacl/math/mpint/mp_int.h"

   auto kOne = 1_mp;  // same as MPInt(1);
   auto kTwo = 2_mp;  // same as MPInt(2);
   auto kZero = 0_mp; // same as MPInt(0);

   MPInt::Add( ... );
   MPInt::AddMod( ... );
   MPInt::Mul( ... );
   MPInt::MulMod( ... );

   MPInt::RandPrimeOver( ... );
   MPInt::RandomLtN( ... )

   // ... for more see: yacl/math/mpint/mp_int.h

**yacl/crypto/tools:** Yacl also provides some theoretical tools such as Random Oralce, Random Permutation, etc.

.. code-block:: cpp

   #include "yacl/crypto/tools/ro.h"
   #include "yacl/crypto/tools/rp.h"
   #include "yacl/crypto/tools/prg.h"

   const auto& RO = RandomOracle::GetDefault();
   auto out = RO.Gen(SecureRandBytes(param));

   const auto& RP = RP::GetDefault();
   auto out = RP.Gen(SecureRandU128());

   Prg prg(SecureRandSeed());
   auto out = prg();

   // ... for more see: yacl/crypto/tools

**yacl/crypto/experimental:** Yacl puts experimental cryptography algorithms here.
