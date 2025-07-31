## OPRF

OPRF是一种用于实现伪随机函数（PRF）的2PC协议，Client提供PRF的输入，Server提供密钥，协议的结果为Client获取PRF的输出，同时Client不能获取有关Server密钥的信息，Server不能获取有关Client输入的信息。

如果Client可以验证Server使用的是某一个特定的密钥，则称为Verifiable OPRF(VOPRF)；在可验证性的基础上，若Client可以提供给Server一部分公共输入，则成为Partial Oblivious PRF(POPRF)。

OPRF由一个底层PRF和一个oblivious evaluation方法组成。

+ 常用的底层PRF包括Naor-Reingold PRF、HashedDH PRF、Dodis-Yampolskiy PRF等。
+ Oblivious evaluation指在协议双方不能获取对方输入的情况下，通过交互式的协议完成相应的运算，这里指计算PRF的结果。

## Hashed Diffie-Hellman OPRF

HashedDH是一类最简单的伪随机函数，使用了抽象为Random Oracle的hash函数来保证伪随机性，即，假设$ H(x) $是一个安全hash函数，则$ f_k^H(x) = H(x)^k $构成一个PRF。

选择随机的$ a $，则$ g^a $可以构成一个简单的hash函数，$ f^H_k(x) = (g^a)^k = g^{ak} $构成一个DH风格的值（类似DH密钥交换中双方的秘密值，$ a $和$ k $分别由hash函数和私钥提供），这样的PRF称为HashDH PRF。

对于此类PRF，oblivious evaluation的方法为blinded exponentiation：

1. Client选择一个blind指数$ r $，计算hash值的指数$ a = H(x)^r $，并发送给Server；
2. Server对blinded element，即$ H(x)^r $进行PRF的处理，得到$ b = (H(x)^{r})^k $，返回给Client，这一步称为blind evaluation，其中，blind指数保证了$ H(x) $不会被Server知道；
3. Client使用$ 1/r $，从Server传递的值当中恢复$ b^{1/r} = H(x)^k $。

## Verifiable Oblivious Pseudorandom Functions

可验证性描述的是输出结果正确性可以验证，在OPRF中，就是Client可以验证输出的$ f_k(x) $是使用了Server私钥$ k $计算的结果。

在HashedDH中，可验证性的实现是通过在Server返回给Client的值中，除了经过oblivious evaluation处理之后的blinded element，附加一个对Server拥有私钥的NIZK证明来实现的。此处，NIZK的public statement为$ (H(x)^r)^k $，对应的witness为私钥$ k $。使用一个经过FS变换的sigma protocol就可以计算这个proof。

更直观一些，可以尝试用Schnorr协议设计一个naive的VOPRF协议：

1. Client选择一个blind指数$ r $，计算hash值的指数$ a = H(x)^r $，并发送给Server；
2. Server计算$ b = (H(x)^{r})^k $，选择随机的$ d $，计算$ c = (H(x)^r)^d,\ s = d + kH_2(c) $，将$ (b,c,s) $发送给Clinet；
3. Client计算$ (H(x)^r)^s $，并与$ c \cdot b^{H_2(c)} $比较，如果相等则通过验证，接着使用$ 1/r $，从Server传递的值当中恢复$ b^{1/r} = H(x)^k $。

## RFC 9497

OPRF是一类已经得到较广泛应用的MPC协议，Cloudflare已经将OPRF应用在密码管理能环节来实现口令安全和匿名化以保证用户数据隐私。IETF为OPRF定义了标准的实现，即RFC 9497。

RFC 9497文档的三种OPRF（标准OPRF，VOPRF，POPRF）都采用HashedDH PRF和blinded exponentiation进行设计。这里简要介绍一下文档定义的OPRF接口。

### OPRF

```shell
Client(input)                             Server(skS)
 -------------------------------------------------------------------
 blind, blindedElement = Blind(input)
                    blindedElement
                    ---------->
                evaluatedElement = BlindEvaluate(skS, blindedElement)
                        evaluatedElement
                        <----------
 output = Finalize(input, blind, evaluatedElement)
```

OPRF协议的过程与上文描述的一致：

1. 先使用随机值$ blind $处理input，得到$ blindElement = H(input)^{blind} $，随机值保证了Client输入的不可见；
2. Server收到$ blindElemet $后，使用$ skS $得到$ evaluatedElement = blindElement^{skS} $，并返回给Client；
3. Client计算$ blind $的逆，计算$ blindElement^{1/blind} $。

### VOPRF

```shell
 Client(input, pkS) <---- pkS ------ Server(skS, pkS) 
 ------------------------------------------------------------------- 
 blind, blindedElement = Blind(input) 
                   blindedElement 
                   ----------> 
                   evaluatedElement, proof = BlindEvaluate(skS, pkS, 
                                                     blindedElement) 
                         evaluatedElement, proof 
                         <---------- 
 output = Finalize(input, blind, evaluatedElement, 
 blindedElement, pkS, proof)
```

在VOPRF协议中，与前文的naive协议不同，采用了batched方式批量生成证明。为此，C/S双方在进行协议交互之前，需要先交换一个公钥，这个公钥只在生成证明的时候使用，对应的是计算PRF使用的私钥$ k $。其生成NIZK证明的大致思路如下：

1. 将公钥$ pkS = g^k $和$ \{H(x_i)^{blind_i}\},\ \{H(x_i)^{blind_i k}\} $进行聚合，得到$ M,Z=M^k $；
2. 生成随机值$ r $，计算$ g^r, M^r $；
3. 采用FS变换，计算上述transcript的hash，记为$ c $；
4. 证明为$ (c, s = r - ck) $.

对上述证明进行验证：

1. 首先仍需要将公钥和$ \{H(x_i)^{blind_i}\},\ \{H(x_i)^{blind_i k}\} $进行聚合，得到$ M,Z $；
2. 然后计算$ g^s+(g^k)^c $和$ M^s + Z^c $；
3. 最后计算上述transcript的hash，并与$ c $进行比较来验证.

可以发现，$ g^s(g^k)^c = g^r/g^{ck} \cdot (g^k)^c = g^r $，$ M^s + Z^c = M^r / M^{ck} \cdot (M^k)^c = M^r $，所以最后计算的hash应当是一样的，而因为$ M,Z $中包含了所有Client的输入和Server进行oblivious evaluation的结果，所以这个NIZK证明可以说明Server的输出是使用与事先交换的公钥对应的私钥$ k $进行生成的。更严谨的completeness和knowledge soundness证明不在这里展开。

### POPRF

```shell
 Client(input, pkS, info) <---- pkS ------ Server(skS, pkS, info)
 -------------------------------------------------------------------
 blind, blindedElement, tweakedKey = Blind(input, info, pkS)
                    blindedElement
                    ---------->
        evaluatedElement, proof = BlindEvaluate(skS, blindedElement,
                                                                info)
                    evaluatedElement, proof
                    <----------
 output = Finalize(input, blind, evaluatedElement,
 blindedElement, proof, info, tweakedKey)
 ```

POPRF中，额外的公共信息$ info $需要和公钥$ pkS $聚合，得到临时密钥$ T = info * pkS $，在Server计算证明以及Client验证证明的时候都需要进行计算，其他部分与VOPRF一致。

## 参考文献

[1] [SoK: Oblivious Pseudorandom Functions](https://eprint.iacr.org/2022/302.pdf)