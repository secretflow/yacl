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

#include "zkp/sumcheck/matmul_check.h"

#include "yacl/base/exception.h"

#include <cmath>

namespace examples::zkp {

FieldElem mat_mat_multiplication(
    const std::shared_ptr<const MultivariatePolynomial>& A,
    const std::shared_ptr<const MultivariatePolynomial>& B,
    const std::vector<FieldElem>& u,
    const std::vector<FieldElem>& v,
    const FieldElem& modulus) {

    size_t num_vars_A = A->get_num_variables();
    size_t num_vars_B = B->get_num_variables();
    size_t log_M = u.size();
    size_t log_P = v.size();

    YACL_ENFORCE(num_vars_A > log_M, "Matrix A must have more variables than challenge vector u.");
    YACL_ENFORCE(num_vars_B > log_P, "Matrix B must have more variables than challenge vector v.");

    size_t log_N_A = num_vars_A - log_M;
    size_t log_N_B = num_vars_B - log_P;

    YACL_ENFORCE(log_N_A == log_N_B, "Inner dimensions of matrices A and B do not match.");
    size_t log_N = log_N_A;

    FieldElem total_sum(0);
    size_t N = 1 << log_N;

    // Iterate over the shared dimension y in {0,1}^log(N)
    for (size_t i = 0; i < N; ++i) {
        std::vector<FieldElem> y(log_N);
        size_t temp_i = i;
        for (size_t j = 0; j < log_N; ++j) {
            y[log_N - 1 - j] = FieldElem(temp_i & 1);
            temp_i >>= 1;
        }

        std::vector<FieldElem> point_A = u;
        point_A.insert(point_A.end(), y.begin(), y.end());
        std::vector<FieldElem> point_B = y;
        point_B.insert(point_B.end(), v.begin(), v.end());

        FieldElem eval_A = A->evaluate(point_A);
        FieldElem eval_B = B->evaluate(point_B);
        FieldElem product;
        FieldElem::MulMod(eval_A, eval_B, modulus, &product);
        FieldElem::AddMod(total_sum, product, modulus, &total_sum);
    }

    return total_sum;
}

FieldElem mat_vec_multiplication(
    const std::shared_ptr<const MultivariatePolynomial>& M,
    const std::shared_ptr<const MultivariatePolynomial>& t,
    const std::vector<FieldElem>& r,
    const FieldElem& modulus) {
    
    size_t num_vars_M = M->get_num_variables();
    size_t num_vars_t = t->get_num_variables();
    size_t log_M_rows = r.size();

    YACL_ENFORCE(num_vars_M > log_M_rows, "Matrix M must have more variables than challenge vector r.");

    size_t log_N_M = num_vars_M - log_M_rows;

    YACL_ENFORCE(log_N_M == num_vars_t, "Inner dimensions of matrix M and vector t do not match.");
    size_t log_N = num_vars_t;

    FieldElem total_sum(0);
    size_t N = 1 << log_N;

    // Iterate over the shared dimension y in {0,1}^log(N)
    for (size_t i = 0; i < N; ++i) {
        std::vector<FieldElem> y(log_N);
        size_t temp_i = i;
        for (size_t j = 0; j < log_N; ++j) {
            y[log_N - 1 - j] = FieldElem(temp_i & 1);
            temp_i >>= 1;
        }

        std::vector<FieldElem> point_M = r;
        point_M.insert(point_M.end(), y.begin(), y.end());
        FieldElem eval_M = M->evaluate(point_M);
        FieldElem eval_t = t->evaluate(y);
        FieldElem product;
        FieldElem::MulMod(eval_M, eval_t, modulus, &product);
        FieldElem::AddMod(total_sum, product, modulus, &total_sum);
    }

    return total_sum;
}

} // namespace examples::zkp