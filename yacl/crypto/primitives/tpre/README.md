# TPRELib: A distributed threshold Proxy Re-Encryption self-developed library based on secret sharing

# 1. Introduction

The access control for source data, secret shares, and result data is currently lacking in privacy computing products, which cannot achieve controllable and quantifiable data (to prevent data leakage and abuse). In addition, in such cryptosystems, there are many implementations based on international passwords, which cannot be applied in application scenarios that require domestic passwords.

By using distributed threshold Proxy Re-Encryption (TPRE) to encrypt source data, secret shares, and result data, secure sharing and dynamic authorization are achieved for them! At the same time, this library implements a new distributed threshold Proxy Re-Encryption algorithm library TPRELib. During the algorithm calculation process, the Chinese national cryptography standard algorithms SM2, SM3 and SM4 are used to replace the international algorithms ECC, SHA-256, and AES.

In summary, this algorithm has the following advantages:

Implemented a lightweight key management system;

Implemented dynamic authorization and access control of data;

Adapted to distributed computing scenarios in privacy computing;

Adapted to distributed computing and data security sharing scenarios in blockchain;

Replace the international cryptographic algorithm with the Chinese national cryptography standard algorithms SM2, SM3 and SM4.

>TPRE is a substitute of [umbral](https://github.com/nucypher/umbral-doc/blob/master/umbral-doc.pdf). It is implemented using C++, and in addition, it replaces algorithms such as ECC and AES with SM2, SM3 and SM4

# 2. Background knowledge

## 2.1 Proxy Re-Encryption

Proxy Re-Encryption is a type of public key cryptography that allows the proxy to convert one public key related ciphertext to another, while the proxy cannot understand any information about the original message; To achieve this, the agent must have a re-encryption key. A Proxy Re-Encryption algorithm typically consists of three roles: data owner Alice, data receiver Bob, and proxy computing proxy. Assuming that the data $m$ has been encrypted into ciphertext $c$ by Alice using her own public key and stored in Proxy, the specific steps of the algorithm are as follows:

1. As the data owner, Alice wants to authorize Bob to use the data $m$, and generates a Re-Encryption key $rk$ for the proxy.

2. After receiving $rk$, the proxy re encrypts the ciphertext $c$ to obtain a new ciphertext $c'$, and send $c'$ to Bob.

3. Bob decrypts $c'$ using his own private key to obtain plaintext data $m$.

## 2.2 Distributed threshold Proxy Re-Encryption

Proxy Re-Encryption is suitable for use in cloud computing scenarios, where the proxy node is a single node with strong computing performance. This is not in line with the existing privacy computing architecture, as it is usually a distributed architecture. Therefore, it is necessary to modify the traditional Proxy Re-Encryption scheme to adapt to distributed computing environments.

Distributed Proxy Re-Encryption refers to splitting a single proxy node in traditional Proxy Re-Encryption into multiple proxy nodes. Therefore, when re encrypting data, multiple proxy nodes are required to participate in collaborative computing.

Considering the flexibility of selecting proxy nodes to participate in calculations, it is necessary to redesign distributed Proxy Re-Encryption to a threshold based distributed Proxy Re-Encryption.

##2.3 Elliptic Curve

The following is the parameter selection for the prime field elliptic curve "sm2p256v1" selected by SM2:

>p = FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFF

>a = FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFC

>b = 28E9FA9E 9D9F5E34 4D5A9E4B CF6509A7 F39789F5 15AB8F92 DDBCBD41 4D940E93

>n = FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF 7203DF6B 21C6052B 53BBF409 39D54123

>g_ x = 32C4AE2C 1F198119 5F990446 6A39C994 8FE30BBF F2660BE1 715A4589 334C74C7\

>g_ y = BC3736A2 F4F6779C 59BDCEE3 6B692153 D0A9877C C62A4740 02DF32E5 2139F0A0

## 2.3  hash function

Using the hash algorithm, construct the following, where $n$ is the order of the elliptic curve and $x$ is the input to the function:

$$h_ x = 1 + \text{Bignum(SM3}(x)||\text{SM3(SM3(}x))) \bmod n-1$$

## 2.4 KEM/DEM

Due to the fact that public key cryptography is a cryptographic algorithm running on algebraic calculations, its computational efficiency is much lower than symmetric cryptography. Therefore, when the amount of data to be encrypted is large, using public key cryptography directly to encrypt data is not a good choice. In this scenario, KEM/DEM encryption can be used.

- KEM refers to the Key Encapsulation Mechanism;

- DEM refers to the Data Encapsulation Mechanism.

The combination of these two mechanisms can provide efficiency in data encryption and decryption, and also reduce communication overhead when ciphertext needs to be transmitted. Specifically, the DEM mechanism is used to protect the original data by using symmetric encryption algorithms to encrypt and protect the original data; KEM is a symmetric key used to protect and encrypt raw data, using a public key encryption algorithm to encrypt and protect the symmetric key.

# 3. Detailed design
## 3.1 Introduction
TPRELib consists of 6 algorithms, namely key pair generation algorithm $\rm GenerateTpreKeyPair()$, Re-Encryption key generation algorithm $\rm GenerateReKey()$, encryption algorithm $\rm Encrypt()$, decryption algorithm $\rm Decrypt()$, Re-Encryption algorithm $\rm ReEncrypt()$, decryption Re-Encryption ciphertext algorithm $\rm DecryptFrags()$:

- ${ \rm GenerateTpreKeyPair} ( 1^\lambda) \to\ (pk_A, sk_A) $: Enter the security parameter $\lambda$ to generate a public private key pair $(pk_A, sk_A)$.
- ${ \rm GenerateReKey} (sk_A, pk_B, N, t) \to ( {rk_i }, i  \in [1, N]) $: Enter the private key of the data holder $sk_ A$, recipient public key $pk_ B$, number of all proxy nodes $N$ and threshold $t$, output re encrypted key set ${rk_i }, i  \in [1, N]$. Here, it refers to the $id$ of the proxy node.
- ${ \rm Encrypt} (pk_A, m)  \to c $: Enter public key $pk_ A$ and plaintext $m$, output ciphertext $c$. Here, we use the traditional hybrid encryption technique for efficiency in the implementation,i.e., not directly using $pk_ A$ encrypts plaintext because it can cause low performance issues. In the underlying encryption, a symmetric encryption algorithm is used.
- ${ \rm Decrypt} (sk_A, c)  \to m$: Enter private key $sk_ A$ and ciphertext $c$, output plaintext $m$. This is the inverse process of the encryption algorithm.

- ${\rm ReEncrypt}(rk_i,c)\to c_i'$: Proxy node input Re-Encryption key $rk_ i$and ciphertext $c$, output new ciphertext $c_ i'$. This refers to the $id$ of the proxy node.
- ${\rm DecryptFrags}({{c_i'}(\text{where},i\in[t,N]),sk_ B} )  \to m $: The input is the new ciphertext set ${c_i '} ( \text {where}, i  \in [t, N])$ with a threshold number and the recipient's private key $sk$, and the output is plaintext $m$.

> In this library, the symmetric encryption algorithm is implemented by SM4, and its symmetric key is randomly generated during the encryption process. The symmetric encryption key is protected by public key encryption TPRE. When generating symmetric encryption, we need to use the cryptographic hash function to build the KDF (Key derivation function) function. This library uses SM3 instead of SHA-2 and other international algorithms to implement the KDF function.

## 3.2 Code Structure

1. `Hash.h/hash.cc` encapsulates the hash function designed through SM3
2. `kdf.h/kdf.cc` encapsulates key derivation functions designed through SM3
3. `Keys.h/keys/cc` encapsulates the public and private keys, re encrypted keys, etc. required in TPRE
4. `Capsule.h/capsule. cc` encapsulates the key ciphertext and data ciphertext generated by TPRE under DEM
5. `tpre.h/tpre.cc` encapsulates the encryption, decryption, Re-Encryption and other higher-order function of the TPRE
# 4.  Usage Scenario
Privacy computing scenarios on web3.0 can be applied, such as:

- Data security sharing
- Data Security Authorization
- Distributed Key Management

# 5. Summary
In order to make up for the shortcomings of existing privacy computing products, a self-developed distributed threshold Proxy Re-Encryption algorithm library TPRELib is developed to achieve dynamic authorization and access control for source data, secret shares, and result data. In TPRELib, some key links use national secret algorithms SM3 and SM4 to replace international algorithms SHA-256 and AES, achieving autonomous control. In order to make up for the shortcomings of existing privacy computing products, a distributed threshold Proxy Re-Encryption algorithm library TPRELib is implemented to achieve dynamic authorization and access control for source data, secret shares, and result data. In TPRELib, some key links are replaced with international algorithms ECC, SHA-256, and AES using Chinese national cryptography standard algorithms SM2, SM3 and SM4.
