
_IV = (
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
)

_T = [0x79CC4519]*16 + [0x7A879D8A]*48

def _rotl(x: int, n: int) -> int:
    # 重要：对 n 取模 32，避免 n>=32 时出现负移位或不一致
    n = n % 32
    return ((x << n) | (x >> (32 - n))) & 0xffffffff

def _P0(x: int) -> int: return x ^ _rotl(x, 9) ^ _rotl(x, 17)
def _P1(x: int) -> int: return x ^ _rotl(x, 15) ^ _rotl(x, 23)

def _FF(j: int, x: int, y: int, z: int) -> int:
    if j < 16: return x ^ y ^ z
    return (x & y) | (x & z) | (y & z)

def _GG(j: int, x: int, y: int, z: int) -> int:
    if j < 16: return x ^ y ^ z
    return (x & y) | (~x & z) & 0xffffffff

def _compress(v, b: bytes):
    W = [0]*68
    W_ = [0]*64
    for i in range(16):
        W[i] = int.from_bytes(b[4*i:4*(i+1)], 'big')
    for i in range(16,68):
        W[i] = (_P1(W[i-16] ^ W[i-9] ^ _rotl(W[i-3], 15)) ^ _rotl(W[i-13],7) ^ W[i-6]) & 0xffffffff
    for i in range(64):
        W_[i] = (W[i] ^ W[i+4]) & 0xffffffff

    A,B,C,D,E,F,G,H = v
    for j in range(64):
        SS1 = _rotl((_rotl(A,12) + E + _rotl(_T[j], j)) & 0xffffffff, 7)
        SS2 = SS1 ^ _rotl(A,12)
        TT1 = (_FF(j,A,B,C) + D + SS2 + W_[j]) & 0xffffffff
        TT2 = (_GG(j,E,F,G) + H + SS1 + W[j]) & 0xffffffff
        D = C
        C = _rotl(B,9)
        B = A
        A = TT1
        H = G
        G = _rotl(F,19)
        F = E
        E = _P0(TT2)
    return [(x ^ y) & 0xffffffff for x,y in zip(v, [A,B,C,D,E,F,G,H])]

class SM3:
    def __init__(self, data: bytes = b''):
        self._v = list(_IV)
        self._buf = b''
        self._len = 0
        if data:
            self.update(data)

    def update(self, data: bytes):
        self._len += len(data)
        data = self._buf + data
        off = 0
        while off + 64 <= len(data):
            blk = data[off:off+64]
            self._v = _compress(self._v, blk)
            off += 64
        self._buf = data[off:]

    def digest(self) -> bytes:
        bitlen = (self._len)*8
        pad = b'\x80' + b'\x00' * ((56 - (self._len + 1) % 64) % 64) + bitlen.to_bytes(8,'big')
        v = list(self._v)
        data = self._buf + pad
        for off in range(0, len(data), 64):
            v = _compress(v, data[off:off+64])
        return b''.join(x.to_bytes(4,'big') for x in v)

    def hexdigest(self) -> str:
        return self.digest().hex()

def sm3(data: bytes) -> bytes:
    return SM3(data).digest()
