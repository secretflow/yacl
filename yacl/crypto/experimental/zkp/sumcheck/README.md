# 更新文档 20251020

## 🧮 Sumcheck Protocol

### 概述

`Sumcheck`  - Interactive Proof，本实现用于验证一个多线性多项式（Multilinear Polynomial）在布尔域 $({0,1}^n)$ 上的求和是否等于给定的声明值 $( H )$。

其中也同时包含了 `Zerocheck` - 验证全为零；`Onecheck` - 验证全为 1 的测试逻辑

### 📘 算法

给定一个多线性多项式：

$$
g(x_1, x_2, ..., x_n)
$$

定义在域 $({F}_p)$ 上（模数为 `modulus_p`），  
我们希望验证：

$$
H = Σ_{x ∈ {0,1}^n} g(x)
$$

即验证一个声称的求和值 $ H $ 是否正确。

### 🧱 代码结构对应

| 模块 | 文件 | 主要函数 | 功能 |
|------|------|-----------|------|
| 协议头文件 | `zkp/sumcheck/sumcheck.h` | `SumcheckProver`, `SumcheckVerifier` | 定义协议类接口 |
| 实现文件 | `zkp/sumcheck/sumcheck.cc` | `ComputeNextRoundPoly`, `ProcessChallenge`, `VerifyRound`, `FinalCheck` | 实现每轮交互逻辑 |
| 测试文件 | `sumcheck_test.cc` | `TEST_F(SumcheckTest, HonestProver)` 等 | 验证协议正确性 |

---

### 🔹 代码关键逻辑对应

#### (1) 计算单变量多项式

```cpp
UnivariatePolynomial SumcheckProver::ComputeNextRoundPoly() {
    FieldElem p_i_at_0(0);
    FieldElem p_i_at_1(0);
    size_t half_size = current_g_evals_.size() / 2;

    for (size_t j = 0; j < half_size; ++j) {
        FieldElem::AddMod(p_i_at_0, current_g_evals_[j], modulus_p_, &p_i_at_0);
        FieldElem::AddMod(p_i_at_1, current_g_evals_[j + half_size],
                           modulus_p_, &p_i_at_1);
    }

    FieldElem c1;
    FieldElem::SubMod(p_i_at_1, p_i_at_0, modulus_p_, &c1);
    return {p_i_at_0, c1}; // p_i(X) = p_i_at_0 + c1 * X
}
```

对应公式：

$$
p_i(X) = p_i(0) + (p_i(1) - p_i(0)) \ · X
$$

---

#### (2) 验证者检查求和一致性

```cpp
FieldElem p_i_at_1;
FieldElem::AddMod(a0, a1, modulus_p_, &p_i_at_1);

FieldElem sum_check;
FieldElem::AddMod(p_i_at_0, p_i_at_1, modulus_p_, &sum_check);

if (sum_check != expected_sum_) { return std::nullopt; }
```

对应公式：

$$
p_i(0) + p_i(1) = H_i
$$

---

#### (3) 更新挑战与下一轮输入

```cpp
FieldElem challenge = RandFieldElem(modulus_p_);
expected_sum_ = EvaluateUnivariate(round_poly, challenge, modulus_p_);
```

对应公式：

$$
H_{i+1} = p_i(r_i)
$$

---

#### (4) 最终检查

```cpp
bool SumcheckVerifier::FinalCheck(...) {
    FieldElem final_eval_check = EvaluateMultilinear(g, challenges_, modulus_p_);
    return final_eval_check == final_eval_from_prover &&
           expected_sum_ == final_eval_from_prover;
}
```

对应公式：

$$
g(r_1, ..., r_n) = H_{n+1}
$$

---

### 🧪 测试代码逻辑

#### ✅ 测试 1：`SumcheckTest.HonestProver`

多项式：

$$
g(x_1, x_2) = x_1 + 2x_2
$$

其取值表为：

| x₁ | x₂ | g(x₁,x₂) |
|----|----|-----------|
| 0  | 0  | 0         |
| 0  | 1  | 2         |
| 1  | 0  | 1         |
| 1  | 1  | 3         |

声明的求和：

$$
H = 0 + 2 + 1 + 3 = 6
$$

```cpp
TEST_F(SumcheckTest, HonestProver) {
  bool success = RunSumcheckProtocol(polynomial_g_, correct_sum_h_, modulus_p_);
  EXPECT_TRUE(success);
}
```

---

#### ❌ 测试 2：`SumcheckTest.FraudProver`

伪造求和 $( H' = 10 $)，实际应为 6。

---

#### ✅ 测试 3：`ZeroCheckTest.HonestProver`

检测零多项式 $ A(x) = 0 $。  

通过验证。

---

#### ❌ 测试 4：`ZeroCheckTest.FraudProver`

$ A(x_1,x_2) = x_2 $，非零多项式。  

---

#### ✅ 测试 5：`OneCheckTest.AllOnesHonestProver`

MLE 多项式上所有点均为 1。  

验证通过。

---

#### ❌ 测试 6：`OneCheckTest.NotAllOnesFraudProver`

有一项为 0，非全 1。

---

#### ❌ 测试 7：`OneCheckTest.NotABitVectorFraudProver`

某项为 5，非布尔值。

## 🍎 将 Matrix Multiplication Check 规约至 Sumcheck

本部分将介绍 `examples::zkp` 下的`矩阵-向量`、`矩阵-矩阵`乘法多项式验证算法及其测试方法。

---

### 多元多项式接口

#### 类定义

```cpp
class MultivariatePolynomial {
public:
    virtual ~MultivariatePolynomial() = default;
    virtual FieldElem evaluate(const std::vector<FieldElem>& point) const = 0;
    virtual size_t get_num_variables() const = 0;
};
```

#### 说明

- `evaluate(point)`：计算多项式在点 `point` 的值。
- `get_num_variables()`：返回多项式的变量数量。

**符号解释**：

- 多项式 $ P(x1, x2, ..., xn) $
- $ point = {r1, r2, ..., rn} $
- $ P(point) = P(r1, r2, ..., rn) $

---

### 矩阵-矩阵乘法验证

#### 函数定义

```cpp
FieldElem mat_mat_multiplication(
    const std::shared_ptr<const MultivariatePolynomial>& A,
    const std::shared_ptr<const MultivariatePolynomial>& B,
    const std::vector<FieldElem>& u,
    const std::vector<FieldElem>& v,
    const FieldElem& modulus);
```

#### 算法公式

给定矩阵 A, B，定义结果矩阵 C：

$$
C(u, v) = Σ_y A(u, y) * B(y, v)
$$

**符号说明**：

- $u$ : 随机行向量挑战（对应矩阵 A 的行）
- $v$ : 随机列向量挑战（对应矩阵 B 的列）
- $y$ : 内维度向量
- $C(u, v)$ : 验证点的矩阵乘积结果

#### 代码逻辑

1. 计算 A, B 的变量数量 `num_vars_A`, `num_vars_B`
2. 根据随机挑战向量 u, v 得到 $log_M$, $log_P$
3. 检查内维度是否匹配：$log_N = num_{vars_A} - log_M = num_{vars_B} - log_P$
4. 对 $y ∈ {0,1}^{log_N}$ 迭代：
   - 组合 evaluation 点：
     - point_A = concat(u, y)
     - point_B = concat(y, v)
   - eval_A = A.evaluate(point_A)
   - eval_B = B.evaluate(point_B)
   - total_sum += eval_A * eval_B mod modulus
5. 返回 `total_sum`

---

### 矩阵-向量乘法验证

#### 函数定义

```cpp
FieldElem mat_vec_multiplication(
    const std::shared_ptr<const MultivariatePolynomial>& M,
    const std::shared_ptr<const MultivariatePolynomial>& t,
    const std::vector<FieldElem>& r,
    const FieldElem& modulus);
```

### Dense 多项式

#### 类定义

```cpp
class DenseMultilinearPolynomial : public MultivariatePolynomial {
public:
    DenseMultilinearPolynomial(std::vector<FieldElem> evaluations, FieldElem modulus);
    FieldElem evaluate(const std::vector<FieldElem>& point) const override;
    size_t get_num_variables() const override;
};
```

#### 说明

- 输入 evaluations 是多项式在所有 {0,1}^n 上的取值。
- evaluate 使用 **多元多项式插值公式**：
  
公式：  
对于 n 个变量和 evaluations g，随机点 r = {r1, r2, ..., rn}：

1. 初始化 evals = g
2. 对 i = 1 到 n：
   - 对每一对 eval_at_0, eval_at_1：
     new_eval = eval_at_0 * (1 - r_i) + eval_at_1 * r_i mod modulus
3. 返回 evals[0]

---

### 测试用例对应关系

#### 测试矩阵-向量乘法

```cpp
FieldElem expected = a->evaluate(r);
FieldElem actual = mat_vec_multiplication(M, t, r, modulus_p_);
EXPECT_EQ(expected, actual);
```

**公式对应**：

- $M = [[1,2],[3,4]]  $
- $t = [5,6]  $
- $a = M * t = [1*5+2*6, 3*5+4*6] = [17,39]  $
- 验证点 $r = [10]  $
- 测试目标：`mat_vec_multiplication(M, t, r)` 与 $a(r)$ 相等

#### 测试矩阵-矩阵乘法

```cpp
FieldElem expected = C->evaluate(uv_point);
FieldElem actual = mat_mat_multiplication(A, B, u, v, modulus_p_);
EXPECT_EQ(expected, actual);
```

**公式对应**：

- $A = [[1,2],[3,4]]$  
- $B = [[5,6],[7,8]]  $
- $C = A * B = [[19,22],[43,50]]  $
- 验证点 $u = [10], v = [20]  $
- 测试目标：`mat_mat_multiplication(A, B, u, v)` 与 $C(u,v)$ 相等

## 🍿 LogUp 协议

### 协议概述

**LogUp** - Lookup Argument 协议。它的核心目标是**证明一个多重集（multiset）`A` 是另一个多重集 `B` 的子集**。

对于 `A` 中的任何一个元素，它在 `A` 中出现的次数，小于或等于它在 `B` 中出现的次数。

### 算法核心

LogUp 协议的巧妙之处在于将集合关系问题转化为一个在随机点上的多项式等式检查。

#### 核心数学公式

协议基于以下恒等式。如果该等式成立，我们就能以极高的概率确信`A`是`B`的子多重集：

$$
Σ (1 / (ζ - a))  =  Σ (m(b) / (ζ - b)) \\
a ∈ A \\
b ∈ B
$$

**公式符号解释**:

* `A`: 要查询的值构成的 **多重集** 对应代码中的 `f_A_evals`。
* `B`: 源表中的值构成的 **集合** 对应代码中的 `f_B_evals`。
* `m(b)`: 值 `b` 在多重集 `A` 中出现的次数，应代码中的 `m_B_evals`。
* `ζ` (Zeta): 一个由 **验证者（Verifier）**提供的**随机挑战**。

#### 协议验证流程

基于 MLE 和 Sumcheck 协议：

1. Prover将 `A`, `B`, `m` 分别表示为多线性多项式 `f_A(x)`, `f_B(y)`, `m_B(y)`。这些多项式的值列表（evaluations）就是原始的数据。

2. Verifier生成一个随机挑战 `ζ` 并发送给Prover。

Prover根据 `ζ` 构造两个辅助多项式 `h_A(x)` 和 `h_B(y)`，它们分别对应核心公式的左右两边：

$$h_A(x) = 1 / (ζ - f_A(x))$$

$$h_B(y) = m_B(y) / (ζ - f_B(y))$$

3. Prover计算`h_A`和`h_B`在各自定义域（布尔超立方体）上的点值之和 `sum_A` 和 `sum_B`，并将其发送给Verifier。Verifier首先检查 `sum_A` 是否等于 `sum_B`。

通过检查以下两个关系式是否恒等于 0 来实现：

$$q_A(x) = h_A(x) * (ζ - f_A(x)) - 1 = 0$$

$$q_B(y) = h_B(y) * (ζ - f_B(y)) - m_B(y) = 0$$

再配合 ZeroCheck 防止 Sum 过程伪造数值。

只有当以上所有检查都通过时，验证才成功。

### 代码实现与公式

#### `LogUpProver::Setup` - 构造辅助多项式

这个函数是Prover的核心。它接收Verifier的挑战`zeta`，并构造`h_A`, `h_B`, `q_A`, `q_B`。

```cpp
// 对应公式中的 (zeta - f_A(x))
FieldElem denominator;
FieldElem::SubMod(zeta_, f_A_val, modulus_p_, &denominator);

// 对应 1 / denominator
FieldElem inv_denominator;
FieldElem::InvertMod(denominator, modulus_p_, &inv_denominator);
h_A_evals.push_back(inv_denominator);
```

```cpp
// 对应公式中的 (zeta - f_B(y))
FieldElem denominator;
FieldElem::SubMod(zeta_, f_B_evals[i], modulus_p_, &denominator);

// 对应 1 / denominator
FieldElem inv_denominator;
FieldElem::InvertMod(denominator, modulus_p_, &inv_denominator);

// 对应 m_B(y) * (1 / denominator)
FieldElem h_B_val;
FieldElem::MulMod(m_B_evals[i], inv_denominator, modulus_p_, &h_B_val);
h_B_evals.push_back(h_B_val);
```

```cpp
FieldElem term1, zeta_minus_fA, q_A_val;
// term1 = h_A(x) * (ζ - f_A(x))
FieldElem::SubMod(zeta_, f_A_evals[i], modulus_p_, &zeta_minus_fA);
FieldElem::MulMod(h_A_->GetEvals()[i], zeta_minus_fA, modulus_p_, &term1);
// q_A_val = term1 - 1
FieldElem::SubMod(term1, one, modulus_p_, &q_A_val);
q_A_evals.push_back(q_A_val);
```

`q_B(y) = h_B(y) * (ζ - f_B(y)) - m_B(y)`

```cpp
FieldElem term1, zeta_minus_fB, q_B_val;
// term1 = h_B(y) * (ζ - f_B(y))
FieldElem::SubMod(zeta_, f_B_evals[i], modulus_p_, &zeta_minus_fB);
FieldElem::MulMod(h_B_->GetEvals()[i], zeta_minus_fB, modulus_p_, &term1);
// q_B_val = term1 - m_B(y)
FieldElem::SubMod(term1, m_B_evals[i], modulus_p_, &q_B_val);
q_B_evals.push_back(q_B_val);
```

#### `LogUpVerifier::Verify` - 执行验证流程

此函数完整地执行了协议的验证步骤。

```cpp
bool LogUpVerifier::Verify(LogUpProver& prover) {
    // 1. Verifier 生成随机挑战 zeta 并发送给 Prover
    zeta_ = RandFieldElem(modulus_p_);
    prover.Setup(zeta_);

    // 2. Prover 计算 h_A 和 h_B 的和 (对应公式中的 Σ)
    auto [claimed_sum_A, claimed_sum_B] = prover.GetClaimedSums();

    // 3. Verifier 检查核心等式是否成立
    if (claimed_sum_A != claimed_sum_B) {
        return false;
    }

    // 4. 对 h_A 和 h_B 运行 Sumcheck 协议，确保 Prover 提供的和是正确的
    if (!RunSumcheckProtocol(h_A->GetEvals(), claimed_sum_A, modulus_p_)) {
        return false;
    }
    if (!RunSumcheckProtocol(h_B->GetEvals(), claimed_sum_B, modulus_p_)) {
        return false;
    }

    // 5. 对 q_A 和 q_B 运行 ZeroCheck 协议，确保 h_A, h_B 构造正确
    if (!RunZeroCheckProtocol(q_A->GetEvals(), modulus_p_)) {
        return false;
    }
    if (!RunZeroCheckProtocol(q_B->GetEvals(), modulus_p_)) {
        return false;
    }

    return true; // 所有检查通过
}
```

### `logup_test.cc` 测试用例分析

测试代码覆盖了协议的四种核心场景。

#### `TEST_F(LogUpTest, HonestProver)`

*   **测试目的**: 验证最基本的、诚实的证明场景。
*   **测试设置**:
    *   `f_A` (查找表): `{5, 10}`
    *   `f_B` (源表): `{3, 5, 10, 20}`
    *   `m_B` (多重性): `{0, 1, 1, 0}` (值5和10在`f_A`中各出现1次)
*   **验证逻辑**: `f_A` 的值域 `{5, 10}` 是 `f_B` 值域的子集，且多重性正确。
*   **预期结果**: `EXPECT_TRUE(success)`，协议必须通过。

#### `TEST_F(LogUpTest, HonestProverWithMultiplicity)`

*   **测试目的**: 验证协议能否正确处理多重集（即`f_A`中包含重复值）的情况。
*   **测试设置**:
    *   `f_A`: `{5, 5, 10, 10}`
    *   `f_B`: `{3, 5, 10, 20}`
    *   `m_B`: `{0, 2, 2, 0}` (值5和10在`f_A`中各出现2次)
*   **验证逻辑**: 此时核心公式两边应相等：
    *   **LHS (左边)**: `1/(ζ-5) + 1/(ζ-5) + 1/(ζ-10) + 1/(ζ-10) = 2/(ζ-5) + 2/(ζ-10)`
    *   **RHS (右边)**: `0/(ζ-3) + 2/(ζ-5) + 2/(ζ-10) + 0/(ζ-20)`
*   **预期结果**: `EXPECT_TRUE(success)`，协议必须通过。

#### `TEST_F(LogUpTest, FraudulentProverSubset)`

*   **测试目的**: **健全性测试**。验证当`f_A`包含一个不在`f_B`中的元素时，协议必须失败。
*   **测试设置**:
    *   `f_A`: `{5, 99}` (99不在`f_B`中)
    *   `f_B`: `{3, 5, 10, 20}`
    *   `m_B`: `{0, 1, 1, 0}`
*   **验证逻辑**: Prover试图作弊，声称`{5, 99}`是`{3, 5, 10, 20}`的子集。此时核心公式不成立，`sum_A`和`sum_B`将不相等（除了极小的概率）。
*   **预期结果**: `EXPECT_FALSE(success)`，协议必须失败。

#### `TEST_F(LogUpTest, FraudulentProverMultiplicity)`

*   **测试目的**: **健全性测试**。验证当`f_A`中某个值的出现次数超过`m_B`声称的次数时，协议必须失败。
*   **测试设置**:
    *   `f_A`: `{5, 5}` (需要两个5)
    *   `f_B`: `{3, 5, 10, 20}`
    *   `m_B`: `{0, 1, 1, 0}` (Prover声称`f_B`只提供了一个5)
*   **验证逻辑**: Prover试图用一个5来满足对两个5的查找需求。核心公式不成立。
    *   **LHS**: `1/(ζ-5) + 1/(ζ-5) = 2/(ζ-5)`
    *   **RHS**: `0/(ζ-3) + 1/(ζ-5) + 1/(ζ-10) + 0/(ζ-20)`
*   **预期结果**: `EXPECT_FALSE(success)`，协议必须失败。