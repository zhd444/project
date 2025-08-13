import random
import hashlib
from ecdsa import NIST256p, SigningKey
from phe import paillier


# 1. 初始化椭圆曲线和参数
curve = NIST256p  # 对应secp256r1，满足DDH假设
order = curve.order  # 曲线阶数
generator = curve.generator  # 生成元


def hash_to_curve(data):
    # 哈希数据到整数
    sha256 = hashlib.sha256(data).digest()
    scalar = int.from_bytes(sha256, 'big') % order

    # 映射到曲线上的点（ generator * scalar ）
    return generator * scalar


# --------------------------
# 2. 生成私有密钥
# --------------------------
k1 = random.randint(1, order - 1)  # P1的私钥
k2 = random.randint(1, order - 1)  # P2的私钥


# 3. 生成Paillier同态加密密钥
paillier_pub, paillier_priv = paillier.generate_paillier_keypair()


# 4. 模拟数据
# P1的用户标识符集合V
V = [
    b"user1_password_hash",
    b"user2_password_hash",  # 与W中的元素交集
    b"user3_password_hash"
]

# P2的泄露数据W（标识符+风险值）
W = [
    (b"leaked_hash1", 10),
    (b"user2_password_hash", 5),  # 与V中的元素交集
    (b"leaked_hash3", 15)
]

# --------------------------
# 5. 协议交互流程
# --------------------------
# Round 1: P1发送 H(v_i)^k1
p1_step1 = []
for v in V:
    h = hash_to_curve(v)  # H(v_i)
    encrypted_v = h * k1  # H(v_i)^k1
    p1_step1.append(encrypted_v)
random.shuffle(p1_step1)  # 打乱顺序

# Round 2: P2发送 H(v_i)^(k1*k2) 和 H(w_j)^k2 + 加密风险值
# 步骤2.1: 处理P1的消息
p2_step2_z = [z * k2 for z in p1_step1]  # H(v_i)^(k1*k2)
random.shuffle(p2_step2_z)
# 转为元组集合便于比较（点的坐标）
Z_set = set((p.x(), p.y()) for p in p2_step2_z)

# 步骤2.2: 处理P2自己的W
p2_step2_w = []
for w, t in W:
    h_w = hash_to_curve(w)  # H(w_j)
    encrypted_w = h_w * k2  # H(w_j)^k2
    encrypted_t = paillier_pub.encrypt(t)  # 加密风险值
    p2_step2_w.append((encrypted_w, encrypted_t))
random.shuffle(p2_step2_w)  # 打乱顺序

# Round 3: P1计算交集并求和
intersection_ciphertexts = []
for enc_w, enc_t in p2_step2_w:
    # 计算 H(w_j)^(k1*k2)
    encrypted_w_k1k2 = enc_w * k1
    # 检查是否在交集中
    if (encrypted_w_k1k2.x(), encrypted_w_k1k2.y()) in Z_set:
        intersection_ciphertexts.append(enc_t)

# 同态求和
sum_cipher = sum(intersection_ciphertexts) if intersection_ciphertexts else paillier_pub.encrypt(0)


# 6. 结果输出
intersection_sum = paillier_priv.decrypt(sum_cipher)
intersection_size = len(intersection_ciphertexts)

print(f"检测到的泄露密码数量：{intersection_size}")
print(f"泄露密码的风险值总和：{intersection_sum}")
