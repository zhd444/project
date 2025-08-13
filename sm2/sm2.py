
from dataclasses import dataclass
from typing import Tuple, Optional, List
from sm3 import sm3
import hmac, hashlib, secrets

# ---- 曲线参数----
q  = 0x8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3
a  = 0x787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498
b  = 0x63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A
Gx = 0x421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D
Gy = 0x0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2
n  = 0x8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7
h  = 1

# ------------------ 基础数论与点运算 ------------------
def mod_inv(x: int, m: int) -> int:
    if x == 0: raise ZeroDivisionError("inverse of zero")
    a_, b_ = x % m, m
    u0, u1 = 1, 0
    while b_:
        q_ = a_ // b_
        a_, b_ = b_, a_ - q_ * b_
        u0, u1 = u1, u0 - q_ * u1
    return u0 % m

def legendre_symbol(a_: int, p_: int) -> int:
    return pow(a_ % p_, (p_ - 1)//2, p_)

def sqrt_mod(a_: int, p_: int) -> Optional[int]:
    """Tonelli-Shanks：在模素数 p_ 下求平方根。找不到时返回 None。"""
    a_ %= p_
    if a_ == 0: return 0
    if p_ % 4 == 3:
        r = pow(a_, (p_ + 1)//4, p_)
        if (r*r) % p_ == a_: return r
        return None
    if legendre_symbol(a_, p_) != 1: return None
    q_, s = p_ - 1, 0
    while q_ % 2 == 0:
        s += 1; q_ //= 2
    z = 2
    while legendre_symbol(z, p_) != p_ - 1: z += 1
    c = pow(z, q_, p_)
    x = pow(a_, (q_ + 1)//2, p_)
    t = pow(a_, q_, p_)
    m = s
    while t != 1:
        i, tt = 1, (t*t) % p_
        while tt != 1:
            tt = (tt*tt) % p_; i += 1
            if i == m: return None
        b = pow(c, 1 << (m - i - 1), p_)
        x = (x * b) % p_
        c = (b * b) % p_
        t = (t * c) % p_
        m = i
    return x

@dataclass
class Point:
    x: Optional[int]
    y: Optional[int]
    inf: bool = False
    def is_inf(self) -> bool: return self.inf

O = Point(None, None, True)

def is_on_curve(P: Point) -> bool:
    if P.inf: return True
    return (P.y * P.y - (P.x*P.x*P.x + a*P.x + b)) % q == 0

def point_add(P: Point, Q: Point) -> Point:
    if P.inf: return Q
    if Q.inf: return P
    if P.x == Q.x:
        if (P.y + Q.y) % q == 0: return O
        l = (3*P.x*P.x + a) * mod_inv(2*P.y % q, q) % q
    else:
        l = (Q.y - P.y) * mod_inv((Q.x - P.x) % q, q) % q
    x3 = (l*l - P.x - Q.x) % q
    y3 = (l*(P.x - x3) - P.y) % q
    return Point(x3, y3, False)

def scalar_mul(k: int, P: Point) -> Point:
    if k % n == 0 or P.inf: return O
    k = k % n
    R = O; Qp = P
    while k:
        if k & 1: R = point_add(R, Qp)
        Qp = point_add(Qp, Qp)
        k >>= 1
    return R

G = Point(Gx, Gy, False)

def _bytes_be(x: int, length: int) -> bytes: return x.to_bytes(length, 'big')
def _int_be(b: bytes) -> int: return int.from_bytes(b, 'big')
def sm3_hash(data: bytes) -> int: return _int_be(sm3(data))

# ------------------ ZA、KDF 与 RFC6979 ------------------
def ZA(IDA: bytes, PA: Point) -> bytes:
    """
    ZA = SM3( ENTLA(16bit) || IDA || a || b || Gx || Gy || xA || yA )
    """
    entl = (len(IDA) * 8).to_bytes(2, 'big')
    blob = (
        entl + IDA +
        _bytes_be(a, 32) + _bytes_be(b, 32) +
        _bytes_be(G.x, 32) + _bytes_be(G.y, 32) +
        _bytes_be(PA.x, 32) + _bytes_be(PA.y, 32)
    )
    return sm3(blob)

def kdf(Z: bytes, klen: int) -> bytes:
    ct = 1; out = b''
    while len(out) < klen:
        out += sm3(Z + ct.to_bytes(4,'big')); ct += 1
    return out[:klen]

def rfc6979_k(d: int, e_bytes: bytes) -> int:
    """
    用 HMAC-DRBG（此处用 SHA-256 版，足够教学）进行 k 的确定性生成。
    若严格对齐 SM 系列，可改为 HMAC-SM3，但 PoC 结论不受影响。
    """
    V = b'\x01' * 32; K = b'\x00' * 32
    x = _bytes_be(d, 32)
    K = hmac.new(K, V + b'\x00' + x + e_bytes, 'sha256').digest()
    V = hmac.new(K, V, 'sha256').digest()
    K = hmac.new(K, V + b'\x01' + x + e_bytes, 'sha256').digest()
    V = hmac.new(K, V, 'sha256').digest()
    T = b''
    while len(T) < 32:
        V = hmac.new(K, V, 'sha256').digest()
        T += V
    return (int.from_bytes(T[:32], 'big') % (n - 1)) + 1

# ------------------ 密钥、签名与验签 ------------------
def keygen() -> Tuple[int, Point]:
    d = secrets.randbelow(n-1) + 1
    P = scalar_mul(d, G)
    return d, P

def sign(d: int, IDA: bytes, M: bytes, deterministic: bool = True) -> Tuple[int,int]:
    PA = scalar_mul(d, G)
    ZA_ = ZA(IDA, PA)
    e = sm3_hash(ZA_ + M)
    while True:
        k = rfc6979_k(d, (ZA_ + M)) if deterministic else (secrets.randbelow(n-1) + 1)
        x1 = scalar_mul(k, G).x % n
        r = (e + x1) % n
        if r == 0 or r + k == n: continue
        s = (mod_inv(1 + d, n) * (k - r*d)) % n
        if s == 0: continue
        return r, s

def verify(PA: Point, IDA: bytes, M: bytes, sig: Tuple[int,int]) -> bool:
    r, s = sig
    if not (1 <= r <= n-1 and 1 <= s <= n-1): return False
    ZA_ = ZA(IDA, PA)
    e = sm3_hash(ZA_ + M)
    t = (r + s) % n
    if t == 0: return False
    x1y1 = point_add(scalar_mul(s, G), scalar_mul(t, PA))
    if x1y1.inf: return False
    R = (e + (x1y1.x % n)) % n
    return R == r

# ------------------ PoC 辅助函数（误用 => 泄密/可恢复） ------------------
def recover_d_from_k_sm2(r: int, s: int, k: int) -> int:
    """
    推导（见 README/讲义）：
      s = (1 + d)^{-1} (k - r d)  (mod n)
    => (s + r)d = k - s
    => d = (k - s) * (s + r)^{-1} (mod n)
    """
    return ((k - s) % n) * mod_inv((s + r) % n, n) % n

def recover_d_from_two_sigs_reuse_k(r1:int, s1:int, r2:int, s2:int) -> int:
    """
    同一用户复用 k 的两次签名消元：
      s1(1+d) = k - r1 d
      s2(1+d) = k - r2 d
    两式相减，解 d：
      d = (s2 - s1) * (s1 - s2 + r1 - r2)^{-1}  (mod n)
    """
    num = (s2 - s1) % n
    den = (s1 - s2 + r1 - r2) % n
    return (num * mod_inv(den, n)) % n

def recover_d_cross_users(k:int, r:int, s:int) -> int:
    """
    两用户共享同一 k，单签也可解出私钥：
      d = (k - s) * (s + r)^{-1} (mod n)
    """
    return ((k - s) % n) * mod_inv((s + r) % n, n) % n

def recover_pub_from_sig_misuse(IDA: bytes, M: bytes, r:int, s:int) -> List['Point']:
    """
    【攻击场景中“验签误用”示例】：如果把 e 错算为 SM3(IDA||M)（未绑定公钥），
    则令 e = SM3(IDA||M)，又有 r = e + x(kG)，即 x(kG) = r - e (mod n)。
    可据此反求 kG 的候选点，再由
      P = (s + r)^{-1} (kG - sG)
    恢复公钥候选。
    注意：这是“验签实现错误”时才可能！
    """
    e = sm3_hash(IDA + M)  # 故意错误：缺少绑定 PA 的 ZA
    Rx = (r - e) % n
    # 解 y^2 = x^3 + a x + b
    alpha = (pow(Rx,3, q) + a*Rx + b) % q
    y = sqrt_mod(alpha, q)
    if y is None: return []
    candidates = []
    for yy in (y, (-y) % q):
        R = Point(Rx, yy, False)
        sG = scalar_mul(s, G)
        inv = mod_inv((s + r) % n, n)
        R_minus_sG = point_add(R, Point(sG.x, (-sG.y) % q, False))
        P = scalar_mul(inv, R_minus_sG)
        if is_on_curve(P): candidates.append(P)
    return candidates

# ------------------（用于跨算法复用 k 的最小 ECDSA） ------------------
def ecdsa_sign_raw(d: int, e: int, k: int) -> Tuple[int,int]:
    """
    在相同的曲线上实现最小 ECDSA（仅为 PoC 服务）。
      r = x(kG) mod n
      s = k^{-1}(e + d r) mod n
    """
    R = scalar_mul(k, G)
    r = R.x % n
    if r == 0: raise ValueError("bad k: r=0")
    s = (mod_inv(k, n) * (e + d*r)) % n
    if s == 0: raise ValueError("bad k: s=0")
    return r, s

def ecdsa_verify_raw(P: Point, e: int, sig: Tuple[int,int]) -> bool:
    r, s = sig
    if not (1 <= r < n and 1 <= s < n): return False
    w = mod_inv(s, n)
    u1 = (e * w) % n
    u2 = (r * w) % n
    X = point_add(scalar_mul(u1, G), scalar_mul(u2, P))
    if X.inf: return False
    return (X.x % n) == r
