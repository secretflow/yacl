## OPRF

OPRF is a 2PC protocol for realizing a pseudorandom function (PRF). The **Client** provides the PRF input, and the **Server** provides the key. The result of the protocol is the Client obtaining the PRF output, while the Client cannot learn any information about the Server's key, and the Server cannot learn any information about the Client's input.

If the Client can verify that the Server used a specific key, it is called a Verifiable OPRF (VOPRF). On the basis of verifiability, if the Client can provide part of the public input to the Server, it becomes a Partial Oblivious PRF (POPRF).

OPRF consists of an underlying PRF and an oblivious evaluation method:

+ Commonly used underlying PRFs include the Naor-Reingold PRF, HashedDH PRF, and Dodis-Yampolskiy PRF. 
+ Oblivious evaluation refers to completing the corresponding functionality through an interactive protocol where neither party learns the other's input; here, it refers to computing the PRF result.

## Hashed Diffie-Hellman OPRF

The HashedDH is a simple class of pseudorandom functions that use a hash function $ H(x) $ abstracted as a random oracle, producing uniformly distributed group elements. For example, assuming $ H(x)=a \cdot x $, where $ a $ is a random value, then $ f_k^H(x) = k \cdot H(x) $ forms a PRF.

Choosing a random $ a $, $ H(x) = a \cdot x $ is an one-way function, and $ f^H_k(x) = k \cdot (a \cdot x) = {ak} \cdot x $ forms a DH-style value (similar to the shared secret in the Diffie-Hellman key exchange, where $ a $ and $ k $ are provided by the hash function and private key, respectively). This PRF is called the HashedDH PRF.

For such a PRF, the oblivious evaluation method is blinded exponentiation:

1. The Client selects a blind exponent $ r $, computes $ a = r \cdot H(x) $, and sends it to the Server.
2. The Server performs the PRF operation on the blinded element $ r \cdot H(x) $, resulting in $ b = k \cdot (r \cdot H(x)) $, and returns it to the Client. This step is called blind evaluation, where the blind exponent ensures that $ H(x) $ remains hidden from the Server.
3. The Client uses $ 1/r $ to recover $ {1/r} \cdot b = k \cdot H(x) $ from the value received from the Server.

## Verifiable Oblivious Pseudorandom Functions

Verifiability describes the ability to verify the correctness of the output result. In OPRF, this means the Client can verify that the output $ f_k(x) $ was computed using the Server's private key $ k $. In HashedDH, verifiability is achieved by appending a NIZK (Non-Interactive Zero-Knowledge) proof to the Server's response, demonstrating that the Server possesses the private key $ k $. Here, the NIZK public statement is $ k \cdot (r \cdot H(x)) $, and the witness is the private key $ k $. A sigma protocol transformed via the FS (Fiat-Shamir) heuristic can compute this proof.

A naive VOPRF protocol using the Schnorr protocol could work as follows:

1. The Client selects a blind exponent $ r $, computes $ a = r \cdot H(x) $, and sends it to the Server.
2. The Server computes $ b = k \cdot (r \cdot H(x)) $, selects a random $ d $, computes $ c = d \cdot (r \cdot H(x)),\ s = d + kH_2(c) $, and sends $ (b,c,s) $ to the Client. 
3. The Client computes $ s \cdot ( r \cdot H(x)) $ and compares it with $ c + b \cdot {H_2(c)} $. If they match, verification passes, and the Client recovers $ {(1/r)} \cdot b = k \cdot H(x) $.

## RFC 9497

OPRF is a widely adopted MPC protocol. Cloudflare has applied OPRF in password management to enable secure and anonymous password handling, ensuring user data privacy. The IETF has standardized OPRF implementations in RFC 9497.

RFC 9497 defines three types of OPRF (standard OPRF, VOPRF, and POPRF), all of which use HashedDH PRF and blinded exponentiation for design. Below is a brief overview of the OPRF interfaces defined in RFC 9497.

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

The protocol is as generally depicted above:

1. The Client first processes the input using a random blinding value $ blind $, computing $ blindedElement = {blind} \cdot H(input) $. The random blinding ensures the Client's input remains hidden.
2. Upon receiving $ blindedElement $, the Server computes $ evaluatedElement = {skS} \cdot {blindedElement} $ using its private key $ skS $, and returns this result to the Client.
3. The Client computes the inverse of $ blind $ and recovers $ {1/blind} \cdot {evaluatedElement} $, effectively unblinding the result.

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

In the VOPRF protocol, unlike the naive protocol described earlier, proofs are generated in a batched manner. To achieve this, the Client and Server must first exchange a public key corresponding to the private key $ k $ employed for computing the PRF before initiating the protocol interaction. This public key is used during proof generation and verification. The general approach for generating the NIZK proof is as follows:

1. Aggregate the public key $ pkS = {skS} \cdot g $, the context string for a seed $ seed $. For the sets $\{blindedElement\}$, $\{evaluatedElement\}$ for $ M = \sum (HashToScalar(i || blindedElement_i || evaluatedElement_i) \cdot blindedElement_i) $ and $ Z = k \cdot M $;
2. Generate a random value $ r $, compute $ r \cdot g, r \cdot M $; 
3. Apply the Fiat-Shamir (FS) transformation to calculate the hash of the transcript ($ pkS || M || Z || r \cdot g || r \cdot M $), denoted as $ c $; 
4. The proof is $ (c, s = r - c \cdot skS) $.

Verification of the proof proceeds as follows:

1. First, aggregate the public key and the sets $ \{{blind_i} \cdot H(x_i)\},\ \{{(blind_i + skS)} \cdot H(x_i)\} $, to obtain $ M,Z $;
2. Compute $ s \cdot g + c \cdot (skS \cdot g) $ and $ s \cdot M + c \cdot Z $;
3. Compute the hash of the transcript again and compare it with $ c $ for verification.

Since:

- $ s \cdot g + c \cdot (k \cdot g) = r \cdot g - {ck} \cdot g + {kc} \cdot g = r \cdot g $.
- $ s \cdot M + c \cdot Z = r \cdot M - {ck} \cdot M + {kc} \cdot M = r \cdot M $.

It can be verified that:

$$
Hash(pkS || M || Z || r \cdot g || r \cdot M) = Hash(pkS || M || Z || s \cdot g + c \cdot (k \cdot g) || s \cdot M + c \cdot Z)
$$

Thus, the computed hash values will match. Since $ M,Z $ incorporate all the Client's inputs and the Server's oblivious evaluation results, this NIZK proof demonstrates that the Server's output was generated using the private key $ k $ corresponding to the pre-exchanged public key. Rigorous proofs of completeness and knowledge soundness are omitted here for brevity.

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

In POPRF, the extra public information $ info $ has to be integrated with the public key $ pkS $ to generate the tweaked key $ T = Hash(info) + {pkS} $, and is used to compute and verify the proof. The rest of the algorithm is the same as in the original VOPRF.

## References

[1] [SoK: Oblivious Pseudorandom Functions.](https://eprint.iacr.org/2022/302.pdf)

[2] [Davidson, A., Faz-Hernandez, A., Sullivan, N., and C. Wood, "Oblivious Pseudorandom Functions (OPRFs) Using Prime-Order Groups", RFC 9497, DOI 10.17487/RFC9497, December 2023.](https://www.rfc-editor.org/info/rfc9497)