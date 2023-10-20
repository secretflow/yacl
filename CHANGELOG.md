# CHANGELOG

All notable changes to this project will be documented in this file.

> Instruction:
>
> - Add `[Feature]` prefix for new features
> - Add `[Bugfix]` prefix for bug fixes
> - Add `[API]` prefix for API changes

## 2023-10-20
- [YACL] 0.4.1 release
- [Feature] Add Sigma-type ZKP Protocols (An unified implementation)
- [Feature] Add ECC Pairing SPI and support to libmcl(ecc, pairing)
- [Feature] Add Multiplication for GF(2^64) and GF(2^128)
- [Bugfix] fix KOS OTe security flaws
- [Feature] Add AVX2 Matrix Transpose

## 2023-05-25
- [YACL] 0.3.3 release
- [Feature] Add Ferret OTe
- [Feature] Add Gywz OTe (Correlated GGM Tree)
- [Feature] Add KOS OTe (warning: KOS still has potential security flaws)

## 2023-02-02
- [YACL] 0.3.1 release
- [Feature] Add `dynamic_bitset` for manipulating bit vectors
- [API] RO now can accept multiple inputs
- [API] Add iknp cot api, improve iknp performance
- [Bugfix] Fix Several m1 related bugs

## 2022-12-08
- [YACL] 0.3.0 release
- [Feature] Add random permutation and correlation-robust hash function
- [Feature] Add OT/OTe benchmark
- [API] Fix randomness implementation
- [API] Re-organize repo layout
- [Bugfix] Fix Random Oralce Usage

## 2022-12-01
- [YACL] 0.2.0 release
- [API] Rename YASL to YACL
- [API] Re-organize repo layout
