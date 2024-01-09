# CHANGELOG

All notable changes to this project will be documented in this file.

> Instruction:
>
> - Add `[Feature]` prefix for new features
> - Add `[Bugfix]` prefix for bug fixes
> - Add `[API]` prefix for API changes

## 2024-01-09
- [YACL] v0.4.2
- [Dependency] Bump: Openssl 3.0.12 (experimental)
- [Feature] Add Softspoken OTe (malicious version)
- [API] Refactor entropy source, drbg, and rand; Refine traditional crypto APIs
- [Bugifx] Multiple bugfixes


## 2023-11-16
- [YACL] v0.4.1.1
- [Feature] Init Global Security Parameters for Yacl [WIP: apply security parameter to all algorithms]
- [Feature] Add Softspoken OTe (semi-honest version)
- [Feature] Add Silent Vole [WIP: optimize MpVole and DualEncode]

## 2023-10-20
- [YACL] v0.4.1
- [Feature] Add Sigma-type ZKP Protocols (An unified implementation)
- [Feature] Add ECC Pairing SPI and support to libmcl(ecc, pairing)
- [Feature] Add Multiplication for GF(2^64) and GF(2^128)
- [Bugfix] fix KOS OTe security flaws
- [Feature] Add AVX2 Matrix Transpose

## 2023-05-25
- [YACL] v0.3.3
- [Feature] Add Ferret OTe
- [Feature] Add Gywz OTe (Correlated GGM Tree)
- [Feature] Add KOS OTe (warning: KOS still has potential security flaws)

## 2023-02-02
- [YACL] v0.3.1
- [Feature] Add `dynamic_bitset` for manipulating bit vectors
- [API] RO now can accept multiple inputs
- [API] Add iknp cot api, improve iknp performance
- [Bugfix] Fix Several m1 related bugs

## 2022-12-08
- [YACL] v0.3.0
- [Feature] Add random permutation and correlation-robust hash function
- [Feature] Add OT/OTe benchmark
- [API] Fix randomness implementation
- [API] Re-organize repo layout
- [Bugfix] Fix Random Oralce Usage

## 2022-12-01
- [YACL] v0.2.0
- [API] Rename YASL to YACL
- [API] Re-organize repo layout
