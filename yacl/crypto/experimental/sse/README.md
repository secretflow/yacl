# Introduction

This folder contains the implementation of searchable symmetric encryption.

## Reference paper

https://eprint.iacr.org/2013/169.pdf

### Description

This paper proposes a highly scalable searchable symmetric encryption (SSE) scheme that aims to solve the search problem in large-scale encrypted datasets, especially to support Boolean queries (e.g., logical operations such as AND, OR, NOT, etc.). While traditional SSE schemes usually support only simple keyword searches, this scheme is able to handle more complex Boolean queries by improving the index structure and query processing, allowing users to combine multiple keywords for searching.

## Implemention

1. **T-Set Instantiation**
    - `tset.h`
    - `tset.cc`
    - `tset_test.cc`
2. **OXT: Oblivious Cross-Tags Protocol**
    - `sse.h`
    - `sse.cc`
    - Test:`sse_test.cc`

## Test

1. To test tset:`bazel test yacl/crypto/experimental/sse/tset_test`
2. To test sse:`bazel test yacl/crypto/experimental/sse/sse_test`

## Data Set

Census Income Dataset
https://tianchi.aliyun.com/dataset/111479
