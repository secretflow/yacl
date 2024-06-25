// Completed by Guowei Ling

#include "ciphertext.h"
#include "config.h"
#include "private_key.h"
#include "yacl/crypto/ecc/ec_point.h"
#include "yacl/math/mpint/mp_int.h"
#include "ahesm2.h"
#include <atomic>
#include "t2.h"
#include "t1.h"


Ciphertext Encrypt(const yacl::math::MPInt& message, const PublicKey& pk) {
    const auto& ec_group = pk.GetEcGroup();
    auto generator = ec_group.GetGenerator();
    yacl::math::MPInt r;
    yacl::math::MPInt::RandomLtN(ec_group.GetOrder(), &r);
    auto c1 = ec_group.MulBase(r);
    const auto& pk_point = pk.GetPoint();
    auto mG = ec_group.MulBase(message);
    auto rpk = ec_group.Mul(pk_point, r);
    auto c2 = ec_group.Add(mG, rpk);
    return Ciphertext{c1, c2};
}

bool CheckDec(const yacl::crypto::EcGroup & ecgroup,const yacl::crypto::EcPoint& m_g,const yacl::math::MPInt& m) {
    yacl::crypto::EcPoint checkmG = ecgroup.MulBase(m);
    return static_cast<bool>(ecgroup.PointEqual(m_g,checkmG));
}

DecryptResult Decrypt(const Ciphertext& ciphertext, const PrivateKey& sk) {
    const auto& ec_group = sk.GetEcGroup();
    auto c1_sk = ec_group.Mul(ciphertext.GetC1(), sk.GetK());
    const auto& c2 = ciphertext.GetC2();
    if (ec_group.PointEqual(c1_sk,c2)) {
        return {yacl::math::MPInt(0), true};
    }
    auto mG = ec_group.Sub(c2, c1_sk);
    auto affmG = ec_group.GetAffinePoint(mG);
    auto affmGx = affmG.x;
    const auto value = t1_loaded.Op_search(affmGx.ToMagBytes(yacl::Endian::native));
    if (value.second) {
        yacl::math::MPInt m(value.first);
        if (CheckDec(ec_group,mG,m)) {
            return {m, true};
        }else{
            return {-(m), true};
        }
    }
    yacl::math::MPInt m; // Declare the variable 'm'
    const auto& t2 = t2_loaded.GetVector();
    std::vector<yacl::math::MPInt> Z;
    Z.resize(Imax);  // 预先分配内存
    for (int i = 1; i <= Imax; ++i) {
        yacl::math::MPInt difference = t2[i].x - affmGx;
        Z[i-1] = difference;
        if (difference.IsZero()) {
            m = yacl::math::MPInt(static_cast<int64_t>(L1)*static_cast<int64_t>(i));
            if (CheckDec(ec_group,mG,m)) {
                return {m, true};
            }else{
                return {-m, true};
            }
        }
    }
    std::vector<yacl::math::MPInt> ZTree;
    ZTree.resize(Treelen);  // 预先分配内存
    for(int i = 0; i < Imax; i++) {
		ZTree[i] = Z[i];
	}
    int offset = Imax;
	int treelen = Imax*2 - 3;
    yacl::math::MPInt P = ec_group.GetField();
	for (int i = 0; i < treelen; i += 2) {
        yacl::math::MPInt product;
        yacl::math::MPInt::Mul(ZTree[i], ZTree[i + 1], &product);

        ZTree[offset] = product.Mod(P);
		offset = offset + 1;
	}
    yacl::math::MPInt treeroot_inv;
    treeroot_inv.Set(ZTree[Treelen-2]);
    treeroot_inv = treeroot_inv.InvertMod(P);
    std::vector<yacl::math::MPInt> ZinvTree;
    ZinvTree.resize(Treelen);  // 预先分配内存
    treelen = Imax*2 - 2;
	int prevfloorflag = treelen;
	int prevfloornum = 1;
	int thisfloorflag = treelen;
    int thisfloornum;
    int thisindex;
    int ztreeindex;
	ZinvTree[prevfloorflag] = treeroot_inv;
	for (int i = 0; i < Ilen; i++) {
		thisfloornum = prevfloornum * 2;
		thisfloorflag = prevfloorflag - thisfloornum;
		for (int f = 0; f < thisfloornum; f++) {
			thisindex = f + thisfloorflag;
			ztreeindex = thisindex ^ 1;
            yacl::math::MPInt product;
            yacl::math::MPInt::Mul(ZTree[ztreeindex], ZinvTree[prevfloorflag+(f/2)], &product);
            ZinvTree[thisindex] = product.Mod(P);
		}
		prevfloorflag = thisfloorflag;
		prevfloornum = prevfloornum * 2;
	}
    auto affmGy = affmG.y;
    for (int j = 1; j <= Imax; j++) {
        yacl::math::MPInt Qx;
        yacl::math::MPInt Qxinv;
        yacl::math::MPInt k;
        yacl::math::MPInt::Add(affmGx, t2[j].x, &k);
        k = k.Mod(P);
        yacl::math::MPInt::Sub(t2[j].y, affmGy, &Qx);
        Qx = Qx.MulMod(ZinvTree[j-1],P);
        Qx = Qx.MulMod(Qx,P);
        Qx = Qx.SubMod(k,P);
        const auto value = t1_loaded.Op_search(Qx.ToMagBytes(yacl::Endian::native));
        if (value.second) {
            m = yacl::math::MPInt(static_cast<int64_t>(L1)*static_cast<int64_t>(j));
            yacl::math::MPInt m1;
            yacl::math::MPInt m2;
            auto jint = yacl::math::MPInt(value.first);
            yacl::math::MPInt::Add(m,jint,&m1);
            yacl::math::MPInt::Sub(m,jint,&m2);
            if (CheckDec(ec_group,mG,m1)) {
                return {m1, true};
            }else{
                return {m2, true};
            }
        }
        yacl::math::MPInt::Sub(-t2[j].y, affmGy, &Qxinv);
        Qxinv = Qxinv.MulMod(ZinvTree[j-1],P);
        Qxinv = Qxinv.MulMod(Qxinv,P);
        Qxinv = Qxinv.SubMod(k,P);
        const auto invvalue = t1_loaded.Op_search(Qxinv.ToMagBytes(yacl::Endian::native));
        if (invvalue.second) {
            m = yacl::math::MPInt(static_cast<int64_t>(-L1)*static_cast<int64_t>(j));
            yacl::math::MPInt m1;
            yacl::math::MPInt m2;
            auto jint = yacl::math::MPInt(invvalue.first);
            yacl::math::MPInt::Add(m,jint,&m1);
            yacl::math::MPInt::Sub(m,jint,&m2);
            if (CheckDec(ec_group,mG,m1)) {
                return {m1, true};
            }else{
                return {m2, true};
            }
        }

	}
    SPDLOG_INFO("Decrypt failed. |m| should be <= {}",Mmax);
    return {yacl::math::MPInt(0), false};
}

DecryptResult search(int start, int end, const yacl::math::MPInt& affm_gx, const yacl::math::MPInt& affm_gy, const std::vector<yacl::math::MPInt>& zinv_tree, const yacl::math::MPInt& p, const yacl::crypto::EcPoint& m_g, const yacl::crypto::EcGroup& ec_group, std::atomic<bool>& found, std::mutex& mtx) {
    const auto& t2 = t2_loaded.GetVector();
    for (int j = start; j < end && !found.load(); j++) {
        yacl::math::MPInt Qx;
        yacl::math::MPInt Qxinv;
        yacl::math::MPInt k;
        yacl::math::MPInt::Add(affm_gx, t2[j].x, &k);
        k = k.Mod(p);
        yacl::math::MPInt::Sub(t2[j].y, affm_gy, &Qx);
        Qx = Qx.MulMod(zinv_tree[j-1], p);
        Qx = Qx.MulMod(Qx, p);
        Qx = Qx.SubMod(k, p);
        const auto value = t1_loaded.Op_search(Qx.ToMagBytes(yacl::Endian::native));
        if (value.second) {
            yacl::math::MPInt m = yacl::math::MPInt(static_cast<int64_t>(L1)*static_cast<int64_t>(j));
            yacl::math::MPInt m1;
            yacl::math::MPInt m2;
            auto jint = yacl::math::MPInt(value.first);
            yacl::math::MPInt::Add(m,jint, &m1);
            yacl::math::MPInt::Sub(m, jint, &m2);
            if (CheckDec(ec_group, m_g, m1)) {
                std::lock_guard<std::mutex> lock(mtx);
                found.store(true);
                return {m1, true};
            } else {
                std::lock_guard<std::mutex> lock(mtx);
                found.store(true);
                return {m2, true};
            }
        }
        yacl::math::MPInt::Sub(-t2[j].y, affm_gy, &Qxinv);
        Qxinv = Qxinv.MulMod(zinv_tree[j-1], p);
        Qxinv = Qxinv.MulMod(Qxinv, p);
        Qxinv = Qxinv.SubMod(k, p);
        const auto invvalue = t1_loaded.Op_search(Qxinv.ToMagBytes(yacl::Endian::native));
        if (invvalue.second) {
            yacl::math::MPInt m = yacl::math::MPInt(static_cast<int64_t>(-L1)*static_cast<int64_t>(j));
            yacl::math::MPInt m1;
            yacl::math::MPInt m2;
            auto jint = yacl::math::MPInt(invvalue.first);
            yacl::math::MPInt::Add(m,jint, &m1);
            yacl::math::MPInt::Sub(m,jint, &m2);
            if (CheckDec(ec_group, m_g, m1)) {
                std::lock_guard<std::mutex> lock(mtx);
                found.store(true);
                return {m1, true};
            } else {
                std::lock_guard<std::mutex> lock(mtx);
                found.store(true);
                return {m2, true};
            }
        }
    }
    return {yacl::math::MPInt(), false}; // 返回一个无效的结果
}

DecryptResult ParDecrypt(const Ciphertext& ciphertext, const PrivateKey& sk) {
    const auto& ec_group = sk.GetEcGroup();
    auto c1_sk = ec_group.Mul(ciphertext.GetC1(), sk.GetK());
    const auto& c2 = ciphertext.GetC2();
    if (ec_group.PointEqual(c1_sk,c2)) {
        return {yacl::math::MPInt(0), true};
    }
    auto mG = ec_group.Sub(c2, c1_sk);
    auto affmG = ec_group.GetAffinePoint(mG);
    auto affmGx = affmG.x;
    yacl::math::MPInt m; 
    const auto value = t1_loaded.Op_search(affmGx.ToMagBytes(yacl::Endian::native));
    if (value.second) {
        m = yacl::math::MPInt(value.first);
        if (CheckDec(ec_group,mG,m)) {
            return {m, true};
        }else{
            return {-(m), true};
        }
    }
    
    const auto& t2 = t2_loaded.GetVector();
    
    std::vector<yacl::math::MPInt> Z;
    Z.resize(Imax);  // 预先分配内存
    for (int j = 1; j <= Imax; ++j) {
        yacl::math::MPInt difference = t2[j].x - affmGx;
        Z[j-1] = difference;
        if (difference.IsZero()) {
            m = yacl::math::MPInt(static_cast<int64_t>(L1)*static_cast<int64_t>(j));
            if (CheckDec(ec_group,mG,m)) {
                return {m, true};
            }else{
                return {-m, true};
            }
        }
    }
    std::vector<yacl::math::MPInt> ZTree;
    ZTree.resize(Treelen);  // 预先分配内存
    for(int i = 0; i < Imax; i++) {
		ZTree[i] = Z[i];
	}
    int offset = Imax;
	int treelen = Imax*2 - 3;
    yacl::math::MPInt P = ec_group.GetField();
	for (int i = 0; i < treelen; i += 2) {
        yacl::math::MPInt product;
        yacl::math::MPInt::Mul(ZTree[i], ZTree[i + 1], &product);
        ZTree[offset] = product.Mod(P);
		offset = offset + 1;
	}
    yacl::math::MPInt treeroot_inv;
    treeroot_inv.Set(ZTree[Treelen-2]);
    treeroot_inv = treeroot_inv.InvertMod(P);
    std::vector<yacl::math::MPInt> ZinvTree;
    ZinvTree.resize(Treelen);  // 预先分配内存
    treelen = Imax*2 - 2;
	int prevfloorflag = treelen;
	int prevfloornum = 1;
	int thisfloorflag = treelen;
    int thisfloornum;
	ZinvTree[prevfloorflag] = treeroot_inv;
	for (int i = 0; i < Ilen; i++) {
		thisfloornum = prevfloornum * 2;
		thisfloorflag = prevfloorflag - thisfloornum;
        yacl::parallel_for(0, thisfloornum,1, [&](int64_t start, int64_t end) {
        for (int f = start; f < end; f++) {
            int thisindex = f + thisfloorflag;
            int ztreeindex = thisindex ^ 1;
            yacl::math::MPInt product;
            yacl::math::MPInt::Mul(ZTree[ztreeindex], ZinvTree[prevfloorflag + (f / 2)], &product);
            ZinvTree[thisindex] = product.Mod(P);
            }
        });
		prevfloorflag = thisfloorflag;
		prevfloornum = prevfloornum * 2;
	}
    auto affmGy = affmG.y;
    const int num_threads = std::thread::hardware_concurrency();
    const int chunk_size = Imax / num_threads;
    std::vector<std::thread> threads;
    std::vector<DecryptResult> results(num_threads);

    std::atomic<bool> found(false);
    std::mutex mtx;
    std::atomic<bool> result_found(false);
    DecryptResult final_result;

    for (int i = 0; i < num_threads; ++i) {
        int start = i * chunk_size+1;
        int end = (i == num_threads - 1) ? (Imax+1) : start + chunk_size;
        threads.emplace_back([&, start, end]() {
            DecryptResult result = search(start, end, affmGx, affmGy, ZinvTree, P, mG, ec_group, found, mtx);
            if (result.success && !result_found.exchange(true)) {
                final_result = result;
                found.store(true);
            }
        });
    }

    for (auto& thread : threads) {
        thread.join();
    }
    if (result_found) {
        return final_result;
    }else{
        SPDLOG_INFO("Decrypt failed. |m| should be <= {}",Mmax);
        return DecryptResult{yacl::math::MPInt(0), false};
    }
}

Ciphertext HAdd(const Ciphertext& ciphertext1, const Ciphertext& ciphertext2,const PublicKey& pk) {
    auto c1 = pk.GetEcGroup().Add(ciphertext1.GetC1(), ciphertext2.GetC1());
    auto c2 = pk.GetEcGroup().Add(ciphertext1.GetC2(), ciphertext2.GetC2());
    return Ciphertext{c1, c2};
}

Ciphertext HSub(const Ciphertext& ciphertext1, const Ciphertext& ciphertext2,const PublicKey& pk) {
    auto c1 = pk.GetEcGroup().Sub(ciphertext1.GetC1(), ciphertext2.GetC1());
    auto c2 = pk.GetEcGroup().Sub(ciphertext1.GetC2(), ciphertext2.GetC2());
    return Ciphertext{c1, c2};
}

Ciphertext HMul(const Ciphertext& ciphertext1, const yacl::math::MPInt & scalar,const PublicKey& pk){
    auto c1 = pk.GetEcGroup().Mul(ciphertext1.GetC1(), scalar);
    auto c2 = pk.GetEcGroup().Mul(ciphertext1.GetC2(), scalar);
    return Ciphertext{c1, c2};
}