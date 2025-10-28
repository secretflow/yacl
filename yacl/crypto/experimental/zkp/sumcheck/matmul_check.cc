// Copyright 2025 Ant Group Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "yacl/crypto/experimental/zkp/sumcheck/matmul_check.h"

#include "yacl/base/exception.h"
#include "yacl/crypto/experimental/zkp/sumcheck/polynomial.h"

namespace examples::zkp {

FieldElem MatMatMultiplication(const MultilinearPolynomial& A,
                               const MultilinearPolynomial& B,
                               const std::vector<FieldElem>& u,
                               const std::vector<FieldElem>& v,
                               const FieldElem& modulus) {
  size_t numVarsA = A.NumVars();
  size_t numVarsB = B.NumVars();
  size_t logM = u.size();
  size_t logP = v.size();

  YACL_ENFORCE(numVarsA > logM,
               "Matrix A must have more variables than challenge vector u.");
  YACL_ENFORCE(numVarsB > logP,
               "Matrix B must have more variables than challenge vector v.");

  size_t logNA = numVarsA - logM;
  size_t logNB = numVarsB - logP;

  YACL_ENFORCE(logNA == logNB,
               "Inner dimensions of matrices A and B do not match.");
  size_t logN = logNA;

  FieldElem totalSum(0);
  size_t N = 1 << logN;

  // Iterate over the shared dimension y in {0,1}^log(N)
  for (size_t i = 0; i < N; ++i) {
    std::vector<FieldElem> y(logN);
    size_t tempI = i;
    for (size_t j = 0; j < logN; ++j) {
      y[logN - 1 - j] = FieldElem(tempI & 1);
      tempI >>= 1;
    }

    std::vector<FieldElem> point_A;
    point_A.reserve(u.size() + y.size());
    point_A.insert(point_A.end(), u.begin(), u.end());
    point_A.insert(point_A.end(), y.begin(), y.end());
    std::vector<FieldElem> point_B;
    point_B.reserve(y.size() + v.size());
    point_B.insert(point_B.end(), y.begin(), y.end());
    point_B.insert(point_B.end(), v.begin(), v.end());

    FieldElem evalA = A.Evaluate(point_A, modulus);
    FieldElem evalB = B.Evaluate(point_B, modulus);
    FieldElem product;
    FieldElem::MulMod(evalA, evalB, modulus, &product);
    FieldElem::AddMod(totalSum, product, modulus, &totalSum);
  }

  return totalSum;
}

FieldElem MatVecMultiplication(const MultilinearPolynomial& M,
                               const MultilinearPolynomial& t,
                               const std::vector<FieldElem>& r,
                               const FieldElem& modulus) {
  size_t numVarsM = M.NumVars();
  size_t numVarsT = t.NumVars();
  size_t logMRows = r.size();

  YACL_ENFORCE(numVarsM > logMRows,
               "Matrix M must have more variables than challenge vector r.");

  size_t logNM = numVarsM - logMRows;

  YACL_ENFORCE(logNM == numVarsT,
               "Inner dimensions of matrix M and vector t do not match.");
  size_t logN = numVarsT;

  FieldElem totalSum(0);
  size_t N = 1 << logN;

  // Iterate over the shared dimension y in {0,1}^log(N)
  for (size_t i = 0; i < N; ++i) {
    std::vector<FieldElem> y(logN);
    size_t tempI = i;
    for (size_t j = 0; j < logN; ++j) {
      y[logN - 1 - j] = FieldElem(tempI & 1);
      tempI >>= 1;
    }

    std::vector<FieldElem> pointM;
    pointM.reserve(r.size() + y.size());
    pointM.insert(pointM.end(), r.begin(), r.end());
    pointM.insert(pointM.end(), y.begin(), y.end());
    FieldElem evalM = M.Evaluate(pointM, modulus);
    FieldElem evalT = t.Evaluate(y, modulus);
    FieldElem product;
    FieldElem::MulMod(evalM, evalT, modulus, &product);
    FieldElem::AddMod(totalSum, product, modulus, &totalSum);
  }

  return totalSum;
}

}  // namespace examples::zkp