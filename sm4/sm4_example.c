#include <stdio.h>
#include <string.h>
#include "sm4.h"

// 测试数据
uint8_t key[SM4_KEY_SIZE] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
uint8_t plaintext[SM4_BLOCK_SIZE] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
uint8_t ciphertext[SM4_BLOCK_SIZE];
uint8_t decrypted[SM4_BLOCK_SIZE];

// GCM测试数据
uint8_t gcm_key[SM4_KEY_SIZE] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
uint8_t gcm_iv[SM4_GCM_IV_SIZE] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b};
uint8_t gcm_aad[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05};
uint8_t gcm_plaintext[] = "Hello, SM4-GCM!";
uint8_t gcm_ciphertext[sizeof(gcm_plaintext)];
uint8_t gcm_decrypted[sizeof(gcm_plaintext)];
uint8_t gcm_tag[SM4_GCM_TAG_SIZE];

// 打印十六进制数据
void print_hex(const char *name, const uint8_t *data, size_t len) {
    printf("%s: ", name);
    for (size_t i = 0; i < len; i++) {
        printf("%02x ", data[i]);
    }
    printf("\n");
}

// 基础SM4测试
void test_sm4_base() {
    sm4_context ctx;
    
    printf("\n--- Testing SM4 Base Implementation ---\n");
    sm4_set_key(key, &ctx);
    
    // 加密
    sm4_encrypt(plaintext, ciphertext, &ctx);
    print_hex("Plaintext", plaintext, SM4_BLOCK_SIZE);
    print_hex("Ciphertext", ciphertext, SM4_BLOCK_SIZE);
    
    // 解密
    sm4_decrypt(ciphertext, decrypted, &ctx);
    print_hex("Decrypted", decrypted, SM4_BLOCK_SIZE);
    
    // 验证
    if (memcmp(plaintext, decrypted, SM4_BLOCK_SIZE) == 0) {
        printf("SM4 Base Test: Passed\n");
    } else {
        printf("SM4 Base Test: Failed\n");
    }
}

// T-table优化的SM4测试
void test_sm4_tbl() {
    sm4_tbl_context ctx;
    
    printf("\n--- Testing SM4 T-table Implementation ---\n");
    sm4_tbl_set_key(key, &ctx);
    
    // 加密
    sm4_tbl_encrypt(plaintext, ciphertext, &ctx);
    print_hex("Plaintext", plaintext, SM4_BLOCK_SIZE);
    print_hex("Ciphertext", ciphertext, SM4_BLOCK_SIZE);
    
    // 使用基础实现解密验证
    sm4_context base_ctx;
    sm4_set_key(key, &base_ctx);
    sm4_decrypt(ciphertext, decrypted, &base_ctx);
    print_hex("Decrypted", decrypted, SM4_BLOCK_SIZE);
    
    // 验证
    if (memcmp(plaintext, decrypted, SM4_BLOCK_SIZE) == 0) {
        printf("SM4 T-table Test: Passed\n");
    } else {
        printf("SM4 T-table Test: Failed\n");
    }
}

// AESNI优化的SM4测试
#ifdef __AES__
void test_sm4_aesni() {
    sm4_aesni_context ctx;
    
    printf("\n--- Testing SM4 AESNI Implementation ---\n");
    sm4_aesni_set_key(key, &ctx);
    
    // 加密
    sm4_aesni_encrypt(plaintext, ciphertext, SM4_BLOCK_SIZE, &ctx);
    print_hex("Plaintext", plaintext, SM4_BLOCK_SIZE);
    print_hex("Ciphertext", ciphertext, SM4_BLOCK_SIZE);
    
    // 使用基础实现解密验证
    sm4_context base_ctx;
    sm4_set_key(key, &base_ctx);
    sm4_decrypt(ciphertext, decrypted, &base_ctx);
    print_hex("Decrypted", decrypted, SM4_BLOCK_SIZE);
    
    // 验证
    if (memcmp(plaintext, decrypted, SM4_BLOCK_SIZE) == 0) {
        printf("SM4 AESNI Test: Passed\n");
    } else {
        printf("SM4 AESNI Test: Failed\n");
    }
}
#endif

// SM4-GCM测试
void test_sm4_gcm() {
    sm4_gcm_context ctx;
    
    printf("\n--- Testing SM4-GCM Implementation ---\n");
    sm4_gcm_init(&ctx, gcm_key);
    sm4_gcm_set_iv(&ctx, gcm_iv, sizeof(gcm_iv));
    
    // 添加附加认证数据
    sm4_gcm_update_aad(&ctx, gcm_aad, sizeof(gcm_aad));
    printf("AAD: ");
    print_hex("", gcm_aad, sizeof(gcm_aad));
    
    // 加密
    printf("Plaintext: %s\n", gcm_plaintext);
    sm4_gcm_encrypt_update(&ctx, gcm_plaintext, sizeof(gcm_plaintext), gcm_ciphertext);
    print_hex("Ciphertext", gcm_ciphertext, sizeof(gcm_ciphertext));
    
    // 生成标签
    sm4_gcm_final(&ctx, gcm_tag);
    print_hex("Tag", gcm_tag, SM4_GCM_TAG_SIZE);
    
    // 解密验证
    sm4_gcm_init(&ctx, gcm_key);
    sm4_gcm_set_iv(&ctx, gcm_iv, sizeof(gcm_iv));
    sm4_gcm_update_aad(&ctx, gcm_aad, sizeof(gcm_aad));
    sm4_gcm_decrypt_update(&ctx, gcm_ciphertext, sizeof(gcm_ciphertext), gcm_decrypted);
    
    uint8_t verify_tag[SM4_GCM_TAG_SIZE];
    sm4_gcm_final(&ctx, verify_tag);
    
    printf("Decrypted: %s\n", gcm_decrypted);
    
    // 验证
    if (memcmp(gcm_plaintext, gcm_decrypted, sizeof(gcm_plaintext)) == 0 &&
        memcmp(gcm_tag, verify_tag, SM4_GCM_TAG_SIZE) == 0) {
        printf("SM4-GCM Test: Passed\n");
    } else {
        printf("SM4-GCM Test: Failed\n");
    }
}

int main() {
    test_sm4_base();
    test_sm4_tbl();
    
#ifdef __AES__
    test_sm4_aesni();
#else
    printf("\nAESNI instructions not supported, skipping AESNI test\n");
#endif
    
    test_sm4_gcm();
    
    return 0;
}
    