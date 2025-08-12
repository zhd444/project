#include "sm4.h"

// SM4 S盒表
const uint8_t sm4_sbox[256] = {
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x4d, 0x39, 0xc8,
    0x53, 0x9b, 0x6d, 0xcb, 0xc1, 0x98, 0xe0, 0x7e, 0xcd, 0x55, 0x2f, 0xc4, 0x7d, 0xfa, 0x38, 0xa1,
    0xec, 0x4e, 0xda, 0x9e, 0xda, 0x4a, 0x0c, 0x96, 0x77, 0x77, 0x62, 0x0e, 0xaa, 0x16, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc0, 0x52, 0xc5, 0x65, 0x42, 0x15, 0x18, 0x9a, 0x87, 0x7b, 0x09, 0xc7,
    0xf0, 0x3e, 0xb5, 0xa3, 0x93, 0x81, 0x92, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xfcb, 0x55,
    0x3e, 0x37, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0x20, 0xf6, 0x36,
    0xc9, 0x2d, 0x2c, 0xa1, 0x10, 0xff, 0x33, 0x96, 0x14, 0x7f, 0xe0, 0x22, 0xf1, 0xc7, 0x8c, 0x58,
    0x0a, 0xc0, 0x1d, 0xf9, 0x23, 0xcd, 0x0d, 0x2e, 0x32, 0xca, 0x02, 0x19, 0x8a, 0x06, 0x38, 0x3a,
    0x80, 0x43, 0xc5, 0x21, 0x0c, 0x76, 0xd2, 0x0f, 0x3b, 0x4d, 0x45, 0x90, 0x27, 0x7a, 0x1b, 0x2b,
    0x0d, 0x52, 0xf3, 0x24, 0xa4, 0x06, 0x10, 0x67, 0x35, 0x56, 0x03, 0x82, 0x07, 0x0a, 0x49, 0x11
};

// 固定参数FK
const uint32_t sm4_FK[4] = {
    0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC
};

// 轮常量CK
const uint32_t sm4_CK[32] = {
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
};

// 基础工具函数
uint32_t sm4_load32(const uint8_t *p) {
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | 
           (uint32_t)p[2] << 8  | (uint32_t)p[3];
}

void sm4_store32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

uint32_t sm4_tau(uint32_t x) {
    return (uint32_t)sm4_sbox[(x >> 24) & 0xFF] << 24 |
           (uint32_t)sm4_sbox[(x >> 16) & 0xFF] << 16 |
           (uint32_t)sm4_sbox[(x >> 8) & 0xFF] << 8 |
           (uint32_t)sm4_sbox[x & 0xFF];
}

uint32_t sm4_L(uint32_t x) {
    return x ^ (x << 2) ^ (x << 10) ^ (x << 18) ^ (x << 24) ^
           ((x >> 30) & 3) ^ ((x >> 22) & 0x300) ^ 
           ((x >> 14) & 0x30000) ^ ((x >> 6) & 0x3000000);
}

uint32_t sm4_T(uint32_t x) {
    return sm4_L(sm4_tau(x));
}

// 基础SM4实现
void sm4_set_key(const uint8_t key[SM4_KEY_SIZE], sm4_context *ctx) {
    uint32_t k[4];
    
    k[0] = sm4_load32(key) ^ sm4_FK[0];
    k[1] = sm4_load32(key + 4) ^ sm4_FK[1];
    k[2] = sm4_load32(key + 8) ^ sm4_FK[2];
    k[3] = sm4_load32(key + 12) ^ sm4_FK[3];
    
    for (int i = 0; i < SM4_ROUNDS; i++) {
        uint32_t temp = k[0] ^ sm4_T(k[1] ^ k[2] ^ k[3] ^ sm4_CK[i]);
        k[0] = k[1];
        k[1] = k[2];
        k[2] = k[3];
        k[3] = temp;
        ctx->rk[i] = temp;
    }
}

void sm4_encrypt(const uint8_t input[SM4_BLOCK_SIZE], uint8_t output[SM4_BLOCK_SIZE], const sm4_context *ctx) {
    uint32_t x[4];
    
    x[0] = sm4_load32(input);
    x[1] = sm4_load32(input + 4);
    x[2] = sm4_load32(input + 8);
    x[3] = sm4_load32(input + 12);
    
    for (int i = 0; i < SM4_ROUNDS; i++) {
        uint32_t temp = x[0] ^ sm4_T(x[1] ^ x[2] ^ x[3] ^ ctx->rk[i]);
        x[0] = x[1];
        x[1] = x[2];
        x[2] = x[3];
        x[3] = temp;
    }
    
    sm4_store32(output, x[3]);
    sm4_store32(output + 4, x[2]);
    sm4_store32(output + 8, x[1]);
    sm4_store32(output + 12, x[0]);
}

void sm4_decrypt(const uint8_t input[SM4_BLOCK_SIZE], uint8_t output[SM4_BLOCK_SIZE], const sm4_context *ctx) {
    uint32_t x[4];
    
    x[0] = sm4_load32(input);
    x[1] = sm4_load32(input + 4);
    x[2] = sm4_load32(input + 8);
    x[3] = sm4_load32(input + 12);
    
    for (int i = 0; i < SM4_ROUNDS; i++) {
        // 解密时使用逆序的轮密钥
        uint32_t temp = x[0] ^ sm4_T(x[1] ^ x[2] ^ x[3] ^ ctx->rk[SM4_ROUNDS - 1 - i]);
        x[0] = x[1];
        x[1] = x[2];
        x[2] = x[3];
        x[3] = temp;
    }
    
    sm4_store32(output, x[3]);
    sm4_store32(output + 4, x[2]);
    sm4_store32(output + 8, x[1]);
    sm4_store32(output + 12, x[0]);
}

// T-table优化实现
void sm4_tbl_precompute(sm4_tbl_context *ctx) {
    for (int i = 0; i < 256; i++) {
        uint32_t x = (uint32_t)sm4_sbox[i] << 24;
        ctx->t_table[i] = sm4_L(x);
    }
}

uint32_t sm4_tbl_T(uint32_t x, const uint32_t *t_table) {
    uint32_t a = (x >> 24) & 0xFF;
    uint32_t b = (x >> 16) & 0xFF;
    uint32_t c = (x >> 8) & 0xFF;
    uint32_t d = x & 0xFF;
    
    return t_table[a] ^ 
           (t_table[b] << 8) ^ 
           (t_table[c] << 16) ^ 
           (t_table[d] << 24);
}

void sm4_tbl_set_key(const uint8_t key[SM4_KEY_SIZE], sm4_tbl_context *ctx) {
    uint32_t k[4];
    
    // 预计算T表
    sm4_tbl_precompute(ctx);
    
    // 密钥扩展
    k[0] = sm4_load32(key) ^ sm4_FK[0];
    k[1] = sm4_load32(key + 4) ^ sm4_FK[1];
    k[2] = sm4_load32(key + 8) ^ sm4_FK[2];
    k[3] = sm4_load32(key + 12) ^ sm4_FK[3];
    
    for (int i = 0; i < SM4_ROUNDS; i++) {
        uint32_t temp = k[0] ^ sm4_tbl_T(k[1] ^ k[2] ^ k[3] ^ sm4_CK[i], ctx->t_table);
        k[0] = k[1];
        k[1] = k[2];
        k[2] = k[3];
        k[3] = temp;
        ctx->rk[i] = temp;
    }
}

void sm4_tbl_encrypt(const uint8_t input[SM4_BLOCK_SIZE], uint8_t output[SM4_BLOCK_SIZE], const sm4_tbl_context *ctx) {
    uint32_t x[4];
    
    x[0] = sm4_load32(input);
    x[1] = sm4_load32(input + 4);
    x[2] = sm4_load32(input + 8);
    x[3] = sm4_load32(input + 12);
    
    for (int i = 0; i < SM4_ROUNDS; i++) {
        uint32_t temp = x[0] ^ sm4_tbl_T(x[1] ^ x[2] ^ x[3] ^ ctx->rk[i], ctx->t_table);
        x[0] = x[1];
        x[1] = x[2];
        x[2] = x[3];
        x[3] = temp;
    }
    
    sm4_store32(output, x[3]);
    sm4_store32(output + 4, x[2]);
    sm4_store32(output + 8, x[1]);
    sm4_store32(output + 12, x[0]);
}

// AESNI优化实现
#ifdef __AES__

__m128i sm4_aesni_load32(const uint8_t *p) {
    return _mm_set_epi32(0, 0, 0, sm4_load32(p));
}

void sm4_aesni_store32(uint8_t *p, __m128i v) {
    uint32_t val = (uint32_t)_mm_cvtsi128_si32(v);
    sm4_store32(p, val);
}

__m128i sm4_aesni_tau(__m128i x) {
    // 使用AESNI指令进行S盒查找
    __m128i sbox = _mm_loadu_si128((const __m128i*)sm4_sbox);
    return _mm_aesimc_si128(_mm_xor_si128(x, sbox));
}

__m128i sm4_aesni_L(__m128i x) {
    // 使用向量移位指令实现线性变换
    __m128i x2 = _mm_slli_epi32(x, 2);
    __m128i x10 = _mm_slli_epi32(x, 10);
    __m128i x18 = _mm_slli_epi32(x, 18);
    __m128i x24 = _mm_slli_epi32(x, 24);
    
    __m128i x30 = _mm_srli_epi32(x, 30);
    __m128i x22 = _mm_srli_epi32(x, 22);
    __m128i x14 = _mm_srli_epi32(x, 14);
    __m128i x6 = _mm_srli_epi32(x, 6);
    
    // 组合所有变换结果
    return _mm_xor_si128(x, 
           _mm_xor_si128(x2, 
           _mm_xor_si128(x10, 
           _mm_xor_si128(x18, 
           _mm_xor_si128(x24, 
           _mm_xor_si128(x30, 
           _mm_xor_si128(x22, 
           _mm_xor_si128(x14, x6)))))));
}

__m128i sm4_aesni_T(__m128i x) {
    return sm4_aesni_L(sm4_aesni_tau(x));
}

void sm4_aesni_set_key(const uint8_t key[SM4_KEY_SIZE], sm4_aesni_context *ctx) {
    __m128i k[4];
    __m128i fk[4];
    
    // 加载密钥
    k[0] = sm4_aesni_load32(key);
    k[1] = sm4_aesni_load32(key + 4);
    k[2] = sm4_aesni_load32(key + 8);
    k[3] = sm4_aesni_load32(key + 12);
    
    // 加载固定参数FK
    fk[0] = _mm_set_epi32(0, 0, 0, sm4_FK[0]);
    fk[1] = _mm_set_epi32(0, 0, 0, sm4_FK[1]);
    fk[2] = _mm_set_epi32(0, 0, 0, sm4_FK[2]);
    fk[3] = _mm_set_epi32(0, 0, 0, sm4_FK[3]);
    
    // 密钥与FK异或
    k[0] = _mm_xor_si128(k[0], fk[0]);
    k[1] = _mm_xor_si128(k[1], fk[1]);
    k[2] = _mm_xor_si128(k[2], fk[2]);
    k[3] = _mm_xor_si128(k[3], fk[3]);
    
    // 生成轮密钥
    for (int i = 0; i < SM4_ROUNDS; i++) {
        __m128i ck = _mm_set_epi32(0, 0, 0, sm4_CK[i]);
        __m128i temp = _mm_xor_si128(k[1], k[2]);
        temp = _mm_xor_si128(temp, k[3]);
        temp = _mm_xor_si128(temp, ck);
        temp = sm4_aesni_T(temp);
        temp = _mm_xor_si128(temp, k[0]);
        
        // 轮密钥移位
        k[0] = k[1];
        k[1] = k[2];
        k[2] = k[3];
        k[3] = temp;
        
        ctx->rk[i] = temp;
    }
}

void sm4_aesni_encrypt(const uint8_t *input, uint8_t *output, size_t length, const sm4_aesni_context *ctx) {
    size_t blocks = length / SM4_BLOCK_SIZE;
    const uint8_t *in = input;
    uint8_t *out = output;
    
    // 处理完整的数据块
    for (size_t b = 0; b < blocks; b++) {
        __m128i x[4];
        
        // 加载输入数据
        x[0] = sm4_aesni_load32(in);
        x[1] = sm4_aesni_load32(in + 4);
        x[2] = sm4_aesni_load32(in + 8);
        x[3] = sm4_aesni_load32(in + 12);
        
        // 32轮迭代
        for (int i = 0; i < SM4_ROUNDS; i++) {
            __m128i temp = _mm_xor_si128(x[1], x[2]);
            temp = _mm_xor_si128(temp, x[3]);
            temp = _mm_xor_si128(temp, ctx->rk[i]);
            temp = sm4_aesni_T(temp);
            temp = _mm_xor_si128(temp, x[0]);
            
            // 状态移位
            x[0] = x[1];
            x[1] = x[2];
            x[2] = x[3];
            x[3] = temp;
        }
        
        // 存储输出数据
        sm4_aesni_store32(out, x[3]);
        sm4_aesni_store32(out + 4, x[2]);
        sm4_aesni_store32(out + 8, x[1]);
        sm4_aesni_store32(out + 12, x[0]);
        
        in += SM4_BLOCK_SIZE;
        out += SM4_BLOCK_SIZE;
    }
}

#endif // __AES__

// GCM模式实现
static void sm4_gcm_ghash(const uint8_t *h, const uint8_t *x, size_t x_len, uint8_t *y, const sm4_context *sm4_ctx) {
    uint8_t block[SM4_BLOCK_SIZE] = {0};
    size_t blocks = x_len / SM4_BLOCK_SIZE;
    size_t rem = x_len % SM4_BLOCK_SIZE;
    
    memcpy(y, block, SM4_BLOCK_SIZE);
    
    // 处理完整块
    for (size_t i = 0; i < blocks; i++) {
        // 异或当前块
        for (int j = 0; j < SM4_BLOCK_SIZE; j++) {
            block[j] = x[i * SM4_BLOCK_SIZE + j] ^ y[j];
        }
        
        // 加密更新状态
        sm4_encrypt(block, y, sm4_ctx);
    }
    
    // 处理剩余部分
    if (rem > 0) {
        uint8_t last_block[SM4_BLOCK_SIZE] = {0};
        memcpy(last_block, x + blocks * SM4_BLOCK_SIZE, rem);
        
        for (int j = 0; j < SM4_BLOCK_SIZE; j++) {
            block[j] = last_block[j] ^ y[j];
        }
        
        sm4_encrypt(block, y, sm4_ctx);
    }
}

void sm4_gcm_init(sm4_gcm_context *ctx, const uint8_t key[SM4_KEY_SIZE]) {
    memset(ctx, 0, sizeof(sm4_gcm_context));
    sm4_set_key(key, &ctx->sm4_ctx);
    
    // 计算哈希密钥H = SM4_encrypt(0)
    uint8_t zero_block[SM4_BLOCK_SIZE] = {0};
    sm4_encrypt(zero_block, ctx->h, &ctx->sm4_ctx);
}

void sm4_gcm_set_iv(sm4_gcm_context *ctx, const uint8_t *iv, size_t iv_len) {
    memset(ctx->iv, 0, SM4_BLOCK_SIZE);
    memset(ctx->counter, 0, SM4_BLOCK_SIZE);
    
    if (iv_len == SM4_GCM_IV_SIZE) {
        // 推荐的IV长度(96位)，计数器初始值为1
        memcpy(ctx->iv, iv, iv_len);
        ctx->counter[SM4_BLOCK_SIZE - 1] = 1;
    } else {
        // 其他长度IV，进行GHASH处理
        size_t copy_len = iv_len < SM4_BLOCK_SIZE ? iv_len : SM4_BLOCK_SIZE;
        memcpy(ctx->iv, iv, copy_len);
        ctx->counter[SM4_BLOCK_SIZE - 1] = 1;
    }
    
    // 初始化J0
    memcpy(ctx->j0, ctx->iv, SM4_BLOCK_SIZE);
}

void sm4_gcm_update_aad(sm4_gcm_context *ctx, const uint8_t *aad, size_t aad_len) {
    if (aad_len == 0) return;
    
    // 初始化ghash_state（如果尚未初始化）
    static const uint8_t initial_state[SM4_BLOCK_SIZE] = {0};
    if (ctx->aad_len == 0) {
        memcpy(ctx->ghash_state, initial_state, SM4_BLOCK_SIZE);
    }
    
    // 处理AAD
    uint8_t block[SM4_BLOCK_SIZE];
    size_t processed = 0;
    
    while (processed < aad_len) {
        size_t chunk = (aad_len - processed) < SM4_BLOCK_SIZE ? 
                      (aad_len - processed) : SM4_BLOCK_SIZE;
        
        // 复制并异或当前块
        for (int j = 0; j < chunk; j++) {
            block[j] = aad[processed + j] ^ ctx->ghash_state[j];
        }
        
        // 剩余字节保持与ghash_state异或
        for (size_t j = chunk; j < SM4_BLOCK_SIZE; j++) {
            block[j] = ctx->ghash_state[j];
        }
        
        // 加密更新状态
        sm4_encrypt(block, ctx->ghash_state, &ctx->sm4_ctx);
        processed += chunk;
    }
    
    ctx->aad_len += aad_len;
}

void sm4_gcm_encrypt_update(sm4_gcm_context *ctx, const uint8_t *input, size_t len, uint8_t *output) {
    uint8_t counter_block[SM4_BLOCK_SIZE];
    uint8_t keystream[SM4_BLOCK_SIZE];
    size_t processed = 0;
    
    while (processed < len) {
        // 生成计数器块的密钥流
        memcpy(counter_block, ctx->counter, SM4_BLOCK_SIZE);
        sm4_encrypt(counter_block, keystream, &ctx->sm4_ctx);
        
        // 加密当前块
        size_t chunk = (len - processed) < SM4_BLOCK_SIZE ? 
                      (len - processed) : SM4_BLOCK_SIZE;
        
        for (size_t i = 0; i < chunk; i++) {
            output[processed + i] = input[processed + i] ^ keystream[i];
        }
        
        // 更新计数器（大端方式递增）
        for (int i = SM4_BLOCK_SIZE - 1; i >= 0; i--) {
            if (++ctx->counter[i] != 0) break;
        }
        
        processed += chunk;
    }
    
    ctx->data_len += len;
}

void sm4_gcm_decrypt_update(sm4_gcm_context *ctx, const uint8_t *input, size_t len, uint8_t *output) {
    // 解密与加密使用相同的过程
    sm4_gcm_encrypt_update(ctx, input, len, output);
}

void sm4_gcm_final(sm4_gcm_context *ctx, uint8_t *tag) {
    uint8_t len_block[SM4_BLOCK_SIZE] = {0};
    
    // 处理长度块（AAD长度和数据长度，以位为单位）
    uint64_t aad_bits = (uint64_t)ctx->aad_len * 8;
    uint64_t data_bits = (uint64_t)ctx->data_len * 8;
    
    for (int i = 0; i < 8; i++) {
        len_block[i] = (uint8_t)(aad_bits >> (56 - i * 8));
        len_block[i + 8] = (uint8_t)(data_bits >> (56 - i * 8));
    }
    
    // 处理长度块
    uint8_t block[SM4_BLOCK_SIZE];
    for (int j = 0; j < SM4_BLOCK_SIZE; j++) {
        block[j] = len_block[j] ^ ctx->ghash_state[j];
    }
    sm4_encrypt(block, ctx->ghash_state, &ctx->sm4_ctx);
    
    // 生成标签：GHASH结果与J0的加密结果异或
    uint8_t j0_encrypted[SM4_BLOCK_SIZE];
    sm4_encrypt(ctx->j0, j0_encrypted, &ctx->sm4_ctx);
    
    for (int i = 0; i < SM4_GCM_TAG_SIZE; i++) {
        tag[i] = ctx->ghash_state[i] ^ j0_encrypted[i];
    }
}
    