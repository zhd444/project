#ifndef SM4_H
#define SM4_H

#include <stdint.h>
#include <string.h>

#define SM4_KEY_SIZE 16    // 128位密钥
#define SM4_BLOCK_SIZE 16  // 128位分组
#define SM4_ROUNDS 32      // 32轮迭代
#define SM4_GCM_IV_SIZE 12 // GCM模式推荐IV长度
#define SM4_GCM_TAG_SIZE 16 // GCM模式标签长度

// SM4算法所需的全局变量声明
extern const uint8_t sm4_sbox[256];
extern const uint32_t sm4_FK[4];
extern const uint32_t sm4_CK[32];

// 基础实现上下文
typedef struct {
    uint32_t rk[SM4_ROUNDS];
} sm4_context;

// T-table优化实现上下文
typedef struct {
    uint32_t rk[SM4_ROUNDS];
    uint32_t t_table[256];
} sm4_tbl_context;

// AESNI优化实现上下文
#ifdef __AES__
#include <wmmintrin.h>  // AESNI指令集头文件
typedef struct {
    __m128i rk[SM4_ROUNDS];
} sm4_aesni_context;
#endif

// GCM模式上下文
typedef struct {
    sm4_context sm4_ctx;
    uint8_t h[SM4_BLOCK_SIZE];       // 哈希密钥
    uint8_t j0[SM4_BLOCK_SIZE];      // 初始计数器值
    uint8_t iv[SM4_BLOCK_SIZE];      // 初始化向量
    uint8_t counter[SM4_BLOCK_SIZE]; // 计数器
    uint8_t tag[SM4_BLOCK_SIZE];     // 认证标签
    uint8_t ghash_state[SM4_BLOCK_SIZE]; // GHASH状态
    size_t aad_len;                  // 附加认证数据长度
    size_t data_len;                 // 加密数据长度
} sm4_gcm_context;

// 基础函数声明
uint32_t sm4_load32(const uint8_t *p);
void sm4_store32(uint8_t *p, uint32_t v);
uint32_t sm4_tau(uint32_t x);
uint32_t sm4_L(uint32_t x);
uint32_t sm4_T(uint32_t x);

// 基础SM4函数
void sm4_set_key(const uint8_t key[SM4_KEY_SIZE], sm4_context *ctx);
void sm4_encrypt(const uint8_t input[SM4_BLOCK_SIZE], uint8_t output[SM4_BLOCK_SIZE], const sm4_context *ctx);
void sm4_decrypt(const uint8_t input[SM4_BLOCK_SIZE], uint8_t output[SM4_BLOCK_SIZE], const sm4_context *ctx);

// T-table优化函数
void sm4_tbl_precompute(sm4_tbl_context *ctx);
uint32_t sm4_tbl_T(uint32_t x, const uint32_t *t_table);
void sm4_tbl_set_key(const uint8_t key[SM4_KEY_SIZE], sm4_tbl_context *ctx);
void sm4_tbl_encrypt(const uint8_t input[SM4_BLOCK_SIZE], uint8_t output[SM4_BLOCK_SIZE], const sm4_tbl_context *ctx);

// AESNI优化函数
#ifdef __AES__
__m128i sm4_aesni_load32(const uint8_t *p);
void sm4_aesni_store32(uint8_t *p, __m128i v);
__m128i sm4_aesni_tau(__m128i x);
__m128i sm4_aesni_L(__m128i x);
__m128i sm4_aesni_T(__m128i x);
void sm4_aesni_set_key(const uint8_t key[SM4_KEY_SIZE], sm4_aesni_context *ctx);
void sm4_aesni_encrypt(const uint8_t *input, uint8_t *output, size_t length, const sm4_aesni_context *ctx);
#endif

// GCM模式函数
void sm4_gcm_init(sm4_gcm_context *ctx, const uint8_t key[SM4_KEY_SIZE]);
void sm4_gcm_set_iv(sm4_gcm_context *ctx, const uint8_t *iv, size_t iv_len);
void sm4_gcm_update_aad(sm4_gcm_context *ctx, const uint8_t *aad, size_t aad_len);
void sm4_gcm_encrypt_update(sm4_gcm_context *ctx, const uint8_t *input, size_t len, uint8_t *output);
void sm4_gcm_decrypt_update(sm4_gcm_context *ctx, const uint8_t *input, size_t len, uint8_t *output);
void sm4_gcm_final(sm4_gcm_context *ctx, uint8_t *tag);

#endif // SM4_H
    