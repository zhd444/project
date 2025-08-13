# poc.py - 可直接运行的一组 PoC 与推导复现
# 运行：python poc.py
# 说明：仅用于安全研究与教学演示，切勿用于真实私钥/生产系统。

from sm2 import (
    keygen, sign, verify, ZA, sm3_hash, G, scalar_mul, n, Point, mod_inv,
    recover_d_from_k_sm2, recover_d_from_two_sigs_reuse_k, recover_d_cross_users,
    recover_pub_from_sig_misuse,
    ecdsa_sign_raw, ecdsa_verify_raw
)
import secrets

def poc_leak_k():
    """
    场景：签名时的随机数 k 被泄漏。
    推导：s = (1+d)^{-1}(k - r d) => d = (k - s) * (s + r)^{-1} (mod n)
    下面强制使用“已知的 k”构造一份 SM2 签名，并用公式还原 d。
    """
    d, P = keygen()
    ID = b'ALICE'
    M = b'leak k example'
    k = secrets.randbelow(n-1) + 1
    e = sm3_hash(ZA(ID, P) + M)
    x1 = (scalar_mul(k, G).x) % n
    r = (e + x1) % n
    s = (mod_inv(1 + d, n) * (k - r*d)) % n
    d_rec = recover_d_from_k_sm2(r, s, k)
    return {"d": d, "recovered": d_rec, "equal": d == d_rec}

def poc_reuse_k_same_user():
    """
    场景：同一用户对两条不同消息复用了相同的 k。
    推导：消去 k 得 d = (s2 - s1) * (s1 - s2 + r1 - r2)^{-1} (mod n)
    """
    d, P = keygen()
    ID = b'ALICE'
    M1, M2 = b'msg one', b'msg two'
    k = secrets.randbelow(n-1) + 1
    e1 = sm3_hash(ZA(ID, P) + M1); x1 = (scalar_mul(k, G).x) % n
    r1 = (e1 + x1) % n; s1 = (mod_inv(1 + d, n) * (k - r1*d)) % n
    e2 = sm3_hash(ZA(ID, P) + M2); x2 = (scalar_mul(k, G).x) % n
    r2 = (e2 + x2) % n; s2 = (mod_inv(1 + d, n) * (k - r2*d)) % n
    d_rec = recover_d_from_two_sigs_reuse_k(r1, s1, r2, s2)
    return {"d": d, "recovered": d_rec, "equal": d == d_rec}

def poc_reuse_k_two_users():
    """
    场景：Alice 与 Bob 意外共享了同一个 k（不同消息/不同身份）。
    推导：对每个签名都可单独用 d = (k - s) * (s + r)^{-1} (mod n) 恢复各自 d。
    """
    dA, PA = keygen()
    dB, PB = keygen()
    IDA, IDB = b'ALICE', b'BOB'
    M1, M2 = b'Alice message', b'Bob message'
    k = secrets.randbelow(n-1) + 1
    e1 = sm3_hash(ZA(IDA, PA) + M1); x = (scalar_mul(k, G).x) % n
    r1 = (e1 + x) % n; s1 = (mod_inv(1 + dA, n) * (k - r1*dA)) % n
    e2 = sm3_hash(ZA(IDB, PB) + M2)
    r2 = (e2 + x) % n; s2 = (mod_inv(1 + dB, n) * (k - r2*dB)) % n
    dA_rec = recover_d_cross_users(k, r1, s1)
    dB_rec = recover_d_cross_users(k, r2, s2)
    return {
        "A": {"d": dA, "rec": dA_rec, "equal": dA == dA_rec},
        "B": {"d": dB, "rec": dB_rec, "equal": dB == dB_rec},
    }

def poc_reuse_k_ecdsa_sm2():
    """
    场景：同一把曲线密钥 d、同一个 k，分别用于 ECDSA 与 SM2 的签名。
    结论：可联立两种签名方程消元恢复 d（讲义给出了显式闭式解）。
    这里用“数值求解”方式侧面验证：已知 (r1,s1) for ECDSA，(r2,s2) for SM2，且共用 k，
    则一定可还原 d（我们直接用 d 是否等于 ground truth 验证）。
    """
    d, P = keygen()
    ID = b'ALICE'
    M_sm2 = b'sm2 message'
    M_ecdsa = b'ecdsa message'
    k = secrets.randbelow(n-1) + 1

    # SM2
    e2 = sm3_hash(ZA(ID, P) + M_sm2)
    x = (scalar_mul(k, G).x) % n
    r2 = (e2 + x) % n
    s2 = (mod_inv(1 + d, n) * (k - r2*d)) % n

    # ECDSA（同一曲线）
    # ECDSA 中 e 通常是 Hash(M)，此处直接用 SM3(M_ecdsa) 的整数
    e1 = sm3_hash(M_ecdsa)
    r1, s1 = ecdsa_sign_raw(d, e1, k)

    # 理论上存在闭式解：d = (s1*s2 - e1) * (r1 - s1*s2 - s1*r2)^{-1} (mod n)
    # 直接验证该公式：
    num = (s1 * s2 - e1) % n
    den = (r1 - (s1 * s2 + s1 * r2) % n) % n
    d_rec = (num * mod_inv(den, n)) % n
    ok = (d_rec == d)

    # 保险起见：也可用方程组数值消元搜索（此处不再赘述）
    return {
        "d": d, "rec": d_rec, "equal": ok,
        "ecdsa": {"r": r1, "s": s1, "e": e1},
        "sm2":   {"r": r2, "s": s2, "e": e2}
    }

def poc_recover_pub_from_sig_misuse():
    """
    场景：验签实现错误（把 e 算成 SM3(IDA||M)，未绑定公钥），
    则可由 (r,s,IDA,M) 恢复公钥候选集合（通常 0 或 2 个）。
    这里展示：我们先用“正确实现”生成 (r,s)，再假设“攻击者端”按错误方式计算 e，
    由此调用 recover_pub_from_sig_misuse() 试图恢复 P。
    """
    d, P = keygen()
    ID = b'ALICE'
    M = b'bind ZA wrongly (for demo)'
    r, s = sign(d, ID, M, deterministic=False)  # 正确实现产生的签名
    cands = recover_pub_from_sig_misuse(ID, M, r, s)
    # 验证：用正确的 verify() 检一下哪些候选是正确公钥
    valid = [C for C in cands if verify(C, ID, M, (r,s))]
    return {
        "trueP": (P.x, P.y),
        "candidates": [(c.x, c.y) for c in cands],
        "valid_under_true_verify": [(v.x, v.y) for v in valid]
    }

# -------------- 教学用“代数伪造”演示（非针对任意指定消息）--------------
def forge_ecdsa_algebraic_demo():
    """
    重要声明：
      这是纯“代数构造”演示，展示 ECDSA 校验等式可被参数化满足。
      它只对构造出来的 e'（并非任意指定消息的哈希）成立，
      而且使用的是程序内随机生成的密钥，不能冒充任何真实人物。
      请勿用于任何欺骗或身份冒充。

    经典构造（教材/讲义常见）：
      任取 u, v ∈ [1, n-1]，令 R' = uG + vP，r' = x(R') mod n
      若 r' = 0 则重选；令 s' = r' * v^{-1} mod n
      定义 e' = r' * u * v^{-1} mod n
      则对公钥 P，(r', s') 对 e' 的 ECDSA 验证成立（代数恒等）。

    我们随机生成一把密钥 d，计算 P=dG，随后按照上式返回 (e', r', s') 并用验证器验证。
    """
    d, P = keygen()

    while True:
        u = secrets.randbelow(n-1) + 1
        v = secrets.randbelow(n-1) + 1
        R1 = scalar_mul(u, G)
        R2 = scalar_mul(v, P)
        R = (R1.x, R1.y)
        # R' = uG + vP
        R = (R1.x, R1.y)
        Rp = Point(R1.x, R1.y, False)
        Rp = (lambda X: X)(Rp)
        Rp = Point(R1.x, R1.y, False)
        Rp = (lambda X: X)(Rp)
        Rp = None  # 为了清晰，我们直接用点加函数：
        Rp = (lambda: None)()  # no-op

        R_ = (lambda: None)()
        R_ = None
        # 真正计算：
        Rsum = None
        Rsum = sm2_point_add = None
        from sm2 import point_add as _add
        Rsum = _add(R1, R2)
        if Rsum.inf:  # 不太可能，重选
            continue
        r = Rsum.x % n
        if r == 0:
            continue
        s = (r * mod_inv(v, n)) % n
        if s == 0:
            continue
        e = (r * u * mod_inv(v, n)) % n

        ok = ecdsa_verify_raw(P, e, (r, s))
        if ok:
            return {
                "pubkey": (P.x, P.y),
                "constructed": {"e": e, "r": r, "s": s},
                "verify_ok": ok
            }

def main():
    print("== poc_leak_k ==")
    print(poc_leak_k())

    print("\n== poc_reuse_k_same_user ==")
    print(poc_reuse_k_same_user())

    print("\n== poc_reuse_k_two_users ==")
    print(poc_reuse_k_two_users())

    print("\n== poc_reuse_k_ecdsa_sm2 ==")
    print(poc_reuse_k_ecdsa_sm2())

    print("\n== poc_recover_pub_from_sig_misuse ==")
    print(poc_recover_pub_from_sig_misuse())

    print("\n== forge_ecdsa_algebraic_demo  ==")
    print(forge_ecdsa_algebraic_demo())

if __name__ == "__main__":
    main()

