// Copyright 2026 Ant Group Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "yacl/crypto/experimental/poly/fp_poly.h"

#include <algorithm>
#include <utility>
#include <vector>

namespace yacl::crypto::experimental::poly {

FpPolynomial::SubproductTree::SubproductTree(const FpContext& c) : ctx(&c) {}

bool FpPolynomial::SubproductTree::Empty() const noexcept {
  return points.empty();
}

std::size_t FpPolynomial::SubproductTree::NumPoints() const noexcept {
  return points.size();
}

std::size_t FpPolynomial::SubproductTree::NumLevels() const noexcept {
  return levels.size();
}

const FpPolynomial& FpPolynomial::SubproductTree::Root() const {
  YACL_ENFORCE(!levels.empty() && !levels.back().empty(),
               "SubproductTree::Root: empty tree");
  return levels.back()[0];
}

void FpPolynomial::SubproductTree::EnsureDerivativeVals(bool need_inv) const {
  if (ctx == nullptr) {
    YACL_THROW_ARGUMENT_ERROR(
        "SubproductTree::EnsureDerivativeVals: ctx is null");
  }
  const std::size_t n = NumPoints();
  if (!dg_ready) {
    if (n == 0) {
      dg_vals.clear();
    } else {
      // G' evaluated on all points
      FpPolynomial dG = Root().Derivative();
      dg_vals = dG.MultiPointEval(*this);
      YACL_ENFORCE(dg_vals.size() == n,
                   "SubproductTree::EnsureDerivativeVals: unexpected dG size");
      for (std::size_t i = 0; i < n; ++i) {
        if (dg_vals[i].v == 0) {
          YACL_THROW_ARGUMENT_ERROR(
              "SubproductTree::EnsureDerivativeVals: dG(x_i)=0 "
              "(points likely not distinct)");
        }
      }
    }
    dg_ready = true;
    inv_dg_ready = false;  // derivative updated; invalidate inverse cache
  }

  if (need_inv && !inv_dg_ready) {
    inv_dg_vals = dg_vals;
    if (!inv_dg_vals.empty()) {
      ctx->BatchInv(inv_dg_vals);
    }
    inv_dg_ready = true;
  }
}

const std::vector<Fp>& FpPolynomial::SubproductTree::DerivativeVals() const {
  EnsureDerivativeVals(false);
  return dg_vals;
}

const std::vector<Fp>& FpPolynomial::SubproductTree::InvDerivativeVals() const {
  EnsureDerivativeVals(true);
  return inv_dg_vals;
}

FpPolynomial::SubproductTree FpPolynomial::SubproductTree::Build(
    const FpContext& ctx, const std::vector<Fp>& xs) {
  SubproductTree T(ctx);
  T.points = xs;
  for (auto& x : T.points) {
    x.v %= ctx.GetModulus();
  }

  if (T.points.empty()) {
    return T;
  }

  // level 0
  std::vector<FpPolynomial> level0;
  level0.reserve(T.points.size());
  for (const auto& xi : T.points) {
    // (x - xi) = (-xi) + 1*x
    FpPolynomial leaf(ctx);
    leaf.Coeffs().reserve(2);
    leaf.Coeffs().push_back(ctx.Neg(xi));
    leaf.Coeffs().push_back(ctx.One());
    leaf.Trim();
    level0.push_back(std::move(leaf));
  }
  T.levels.push_back(std::move(level0));

  // upper levels
  while (T.levels.back().size() > 1) {
    const auto& prev = T.levels.back();
    std::vector<FpPolynomial> nxt;
    nxt.reserve((prev.size() + 1) / 2);

    for (std::size_t i = 0; i < prev.size(); i += 2) {
      if (i + 1 < prev.size()) {
        nxt.push_back(prev[i].Mul(prev[i + 1]));
      } else {
        nxt.push_back(prev[i]);  // carry
      }
    }
    T.levels.push_back(std::move(nxt));
  }

  return T;
}

std::vector<std::vector<FpPolynomial>> FpPolynomial::RemainderTree(
    const SubproductTree& tree) const {
  RequireContext();
  if (tree.ctx == nullptr) {
    YACL_THROW_ARGUMENT_ERROR("FpPolynomial::RemainderTree: tree.ctx is null");
  }
  if (ctx_->GetModulus() != tree.ctx->GetModulus()) {
    YACL_THROW_ARGUMENT_ERROR("FpPolynomial::RemainderTree: modulus mismatch");
  }

  const FpContext& F = *ctx_;

  const std::size_t n = tree.NumPoints();
  if (n == 0) {
    return {};  // 空树
  }

  if (tree.levels.empty() || tree.levels[0].size() != n) {
    YACL_THROW_ARGUMENT_ERROR(
        "FpPolynomial::RemainderTree: malformed tree (levels[0] size "
        "mismatch)");
  }

  const std::size_t L = tree.NumLevels();
  if (L == 0) {
    YACL_THROW_ARGUMENT_ERROR(
        "FpPolynomial::RemainderTree: malformed tree (no levels)");
  }

  // rem 与 tree.levels 形状一致
  std::vector<std::vector<FpPolynomial>> rem;
  rem.reserve(L);
  for (std::size_t level = 0; level < L; ++level) {
    rem.emplace_back(tree.levels[level].size(), FpPolynomial(F));
  }

  const std::size_t top = L - 1;

  // 顶层：f mod root
  rem[top][0] = this->Mod(tree.levels[top][0]);

  // 自顶向下传播：child_rem = parent_rem mod child_modulus_poly
  for (std::size_t level = top; level-- > 0;) {
    // 从 level+1 的每个结点，传播到 level 的孩子
    const std::size_t parent_level = level + 1;

    for (std::size_t idx = 0; idx < rem[parent_level].size(); ++idx) {
      const FpPolynomial& r_parent = rem[parent_level][idx];

      const std::size_t left = idx * 2;
      if (left < rem[level].size()) {
        rem[level][left] = r_parent.Mod(tree.levels[level][left]);
      }

      const std::size_t right = left + 1;
      if (right < rem[level].size()) {
        rem[level][right] = r_parent.Mod(tree.levels[level][right]);
      }
    }
  }

  return rem;
}

std::vector<Fp> FpPolynomial::MultiPointEvalNaive(
    const std::vector<Fp>& xs) const {
  RequireContext();
  const FpContext& F = *ctx_;
  std::vector<Fp> ys;
  ys.reserve(xs.size());
  for (Fp x : xs) {
    x.v %= F.GetModulus();
    ys.push_back(Eval(x));
  }
  return ys;
}

std::vector<Fp> FpPolynomial::MultiPointEval(const SubproductTree& tree) const {
  RequireContext();
  if (tree.ctx == nullptr) {
    YACL_THROW_ARGUMENT_ERROR(
        "FpPolynomial::MultiPointEval(tree): tree.ctx is null");
  }
  if (ctx_->GetModulus() != tree.ctx->GetModulus()) {
    YACL_THROW_ARGUMENT_ERROR(
        "FpPolynomial::MultiPointEval(tree): modulus mismatch");
  }

  const FpContext& F = *ctx_;
  const std::size_t n = tree.NumPoints();
  std::vector<Fp> ys(n, F.Zero());
  if (n == 0) {
    return ys;
  }

  auto rem = RemainderTree(tree);

  // rem[0][i] = f mod (x-x_i) = 常数多项式 [f(x_i)]
  YACL_ENFORCE(!rem.empty() && rem[0].size() == n,
               "FpPolynomial::MultiPointEval: unexpected RemainderTree shape");

  for (std::size_t i = 0; i < n; ++i) {
    ys[i] = rem[0][i].ConstantTerm();
  }
  return ys;
}

std::vector<Fp> FpPolynomial::MultiPointEval(const std::vector<Fp>& xs) const {
  RequireContext();
  SubproductTree T = SubproductTree::Build(*ctx_, xs);
  return MultiPointEval(T);
}

FpPolynomial FpPolynomial::InterpolateLagrangeNaive(const FpContext& ctx,
                                                    const std::vector<Fp>& xs,
                                                    const std::vector<Fp>& ys) {
  if (xs.size() != ys.size()) {
    YACL_THROW_ARGUMENT_ERROR("InterpolateLagrangeNaive: xs.size != ys.size");
  }
  const std::size_t n = xs.size();
  FpPolynomial result(ctx);
  if (n == 0) {
    return result;
  }

  // 归一化输入
  std::vector<Fp> X = xs;
  std::vector<Fp> Y = ys;
  for (auto& x : X) {
    x.v %= ctx.GetModulus();
  }
  for (auto& y : Y) {
    y.v %= ctx.GetModulus();
  }

  // G(x) = Π (x - x_j)  [degree n]
  FpPolynomial G(ctx, {ctx.One()});
  for (std::size_t j = 0; j < n; ++j) {
    FpPolynomial lin(ctx);
    lin.Coeffs().reserve(2);
    lin.Coeffs().push_back(ctx.Neg(X[j]));
    lin.Coeffs().push_back(ctx.One());
    lin.Trim();
    G = G.Mul(lin);
  }

  // dG(x_i) = Π_{j!=i} (x_i - x_j)  (O(n^2) via naive multipoint eval)
  FpPolynomial dG = G.Derivative();
  std::vector<Fp> dG_vals = dG.MultiPointEvalNaive(X);
  YACL_ENFORCE(dG_vals.size() == n,
               "InterpolateLagrangeNaive: unexpected dG size");
  for (std::size_t i = 0; i < n; ++i) {
    if (dG_vals[i].v == 0) {
      YACL_THROW_ARGUMENT_ERROR(
          "InterpolateLagrangeNaive: duplicate points (dG(x_i)=0)");
    }
  }

  // a_i = y_i / dG(x_i)
  std::vector<Fp> weights(n, ctx.Zero());
  for (std::size_t i = 0; i < n; ++i) {
    weights[i] = ctx.Div(Y[i], dG_vals[i]);
  }

  // Synthetic division helper: G / (x - xi) (monic divisor), returns degree n-1
  // quotient.
  const auto& gc = G.Coeffs();
  YACL_ENFORCE(gc.size() == n + 1,
               "InterpolateLagrangeNaive: unexpected G degree");
  auto divide_by_linear = [&](Fp xi) {
    std::vector<Fp> q(n, ctx.Zero());
    q[n - 1] = gc[n];  // leading coeff
    for (std::size_t k = n - 1; k > 0; --k) {
      // q[k-1] = gc[k] + xi * q[k]
      Fp t = ctx.Mul(xi, q[k]);
      q[k - 1] = ctx.Add(gc[k], t);
    }
    return q;
  };

  std::vector<Fp> res(n, ctx.Zero());  // degree <= n-1
  for (std::size_t i = 0; i < n; ++i) {
    std::vector<Fp> q = divide_by_linear(X[i]);  // G(x)/(x - x_i)
    const Fp wi = weights[i];
    if (wi.v == 0) {
      continue;
    }
    for (std::size_t k = 0; k < n; ++k) {
      res[k] = ctx.Add(res[k], ctx.Mul(wi, q[k]));
    }
  }

  FpPolynomial out(ctx, std::move(res));
  out.Trim();
  return out;
}

FpPolynomial FpPolynomial::InterpolateSubproductTree(
    const SubproductTree& tree, const std::vector<Fp>& ys) {
  if (tree.ctx == nullptr) {
    YACL_THROW_ARGUMENT_ERROR("InterpolateSubproductTree: tree.ctx is null");
  }
  const FpContext& F = *tree.ctx;

  const std::size_t n = tree.NumPoints();
  if (ys.size() != n) {
    YACL_THROW_ARGUMENT_ERROR(
        "InterpolateSubproductTree: ys.size != number of points");
  }
  if (n == 0) {
    return FpPolynomial(F);  // 零多项式
  }
  if (tree.levels.empty() || tree.levels[0].size() != n) {
    YACL_THROW_ARGUMENT_ERROR(
        "InterpolateSubproductTree: malformed tree (levels[0] size mismatch)");
  }

  // cached inv(dG(x_i))
  const auto& inv_dvals = tree.InvDerivativeVals();

  // a_i = y_i * inv(dG(x_i))
  std::vector<Fp> a(n, F.Zero());
  for (std::size_t i = 0; i < n; ++i) {
    Fp yi = ys[i];
    yi.v %= F.GetModulus();
    a[i] = F.Mul(yi, inv_dvals[i]);
  }

  // 6) 自底向上合并：
  // 在每个结点 S 上维护 F_S(x) = Σ_{i in S} a_i * (M_S(x)/(x-x_i))
  // 叶子：F_{ {i} } = a_i (常数多项式)
  std::vector<std::vector<FpPolynomial>> Flevels;
  Flevels.reserve(tree.NumLevels());

  // level 0 (leaf): constant polys
  {
    std::vector<FpPolynomial> L0;
    L0.reserve(n);
    for (std::size_t i = 0; i < n; ++i) {
      FpPolynomial leaf(F);
      if (a[i].v != 0) {
        leaf.Coeffs().push_back(a[i]);  // 常数项
      }
      leaf.Trim();
      L0.push_back(std::move(leaf));
    }
    Flevels.push_back(std::move(L0));
  }

  // level k>0: combine pairs
  for (std::size_t level = 1; level < tree.levels.size(); ++level) {
    const auto& prevF = Flevels[level - 1];
    const auto& prevM = tree.levels[level - 1];  // 同层的 M 子树多项式（产品）

    if (prevF.size() != prevM.size()) {
      YACL_THROW_ARGUMENT_ERROR(
          "InterpolateSubproductTree: tree malformed (prevF size != prevM "
          "size)");
    }

    std::vector<FpPolynomial> cur;
    cur.reserve((prevF.size() + 1) / 2);

    for (std::size_t i = 0; i < prevF.size(); i += 2) {
      if (i + 1 < prevF.size()) {
        // parent = F_left*M_right + F_right*M_left
        FpPolynomial t1 = prevF[i].Mul(prevM[i + 1]);
        FpPolynomial t2 = prevF[i + 1].Mul(prevM[i]);
        FpPolynomial sum = t1.Add(t2);
        sum.Trim();
        cur.push_back(std::move(sum));
      } else {
        // odd carry: parent is same as child
        cur.push_back(prevF[i]);
      }
    }

    Flevels.push_back(std::move(cur));
  }

  YACL_ENFORCE(!Flevels.empty() && !Flevels.back().empty(),
               "InterpolateSubproductTree: internal error (empty result)");

  FpPolynomial result = Flevels.back()[0];
  result.Trim();
  return result;
}

}  // namespace yacl::crypto::experimental::poly
