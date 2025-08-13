from sm2 import (
    Point, G, n, sm3_hash, scalar_mul, point_add,
    verify, keygen, O
)
import secrets


def forge_satoshi_signature(pa: Point, ida: bytes, message: bytes) -> tuple[int, int]:
    """
    伪造中本聪的SM2签名
    :param pa: 中本聪的公钥（已知）
    :param ida: 中本聪的标识符（
    :param message: 待签名消息
    :return: 伪造的签名(r, s)
    """
    print("开始伪造中本聪签名...")

    while True:
        # 1. 随机选择r和s'
        r = secrets.randbelow(n - 1) + 1  # r ∈ [1, n-1]
        s_prime = secrets.randbelow(n - 1) + 1  # s' ∈ [1, n-1]

        # 2. 计算t = (r + s') mod n
        t = (r + s_prime) % n
        if t == 0:
            continue  # 跳过t=0的情况

        # 3. 计算s'G + tP，获取x1
        s_g = scalar_mul(s_prime, G)
        t_p = scalar_mul(t, pa)
        x1y1 = point_add(s_g, t_p)

        if x1y1.is_inf():
            continue  # 跳过无穷远点

        x1 = x1y1.x % n

        # 4. 计算目标e值：e = (r - x1) mod n
        e_target = (r - x1) % n

        # 5. 搜索符合条件的ZA
        za_fake = None
        for i in range(100000):
            # 生成伪造的ZA（32字节随机数）
            za_candidate = secrets.token_bytes(32)
            # 计算e值
            e_candidate = sm3_hash(za_candidate + message) % n
            if e_candidate == e_target:
                za_fake = za_candidate
                print(f"找到有效ZA，尝试次数: {i + 1}")
                break

        if za_fake is None:
            print("未找到有效ZA，重试...")
            continue

        # 6. 验证伪造签名
        def verify_with_fake_za():
            e = sm3_hash(za_fake + message) % n
            t_verify = (r + s_prime) % n
            if t_verify == 0:
                return False
            s_g_verify = scalar_mul(s_prime, G)
            t_p_verify = scalar_mul(t_verify, pa)
            x1_verify = point_add(s_g_verify, t_p_verify)
            if x1_verify.is_inf():
                return False
            R = (e + x1_verify.x % n) % n
            return R == r

        if verify_with_fake_za():
            print("签名伪造成功！")
            return (r, s_prime)


def main():
    # 模拟中本聪的密钥对
    print("=== 模拟环境初始化 ===")
    satoshi_d, satoshi_pa = keygen()
    print(f"中本聪公钥 x: 0x{satoshi_pa.x:064x}")
    print(f"中本聪公钥 y: 0x{satoshi_pa.y:064x}")

    # 伪造参数
    ida = b"Satoshi Nakamoto"  # 中本聪标识符
    message = b"I am zhongbencong"  # 待签名消息

    # 执行伪造
    fake_sig = forge_satoshi_signature(satoshi_pa, ida, message)
    r, s = fake_sig
    print(f"\n伪造签名结果:")
    print(f"r: 0x{r:064x}")
    print(f"s: 0x{s:064x}")

    # 验证伪造签名（使用标准验证逻辑）
    print("\n=== 签名验证结果 ===")
    is_valid = verify(satoshi_pa, ida, message, fake_sig)
    print(f"标准验证: {'通过' if is_valid else '失败'}")
    print("提示: 标准验证可能失败，需配合伪造的ZA值使用")


if __name__ == "__main__":
    main()