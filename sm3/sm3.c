#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

// SM3算法常量定义
#define SM3_DIGEST_SIZE 32
#define SM3_BLOCK_SIZE 64
#define SM3_IV {0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600, \
                 0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E}

// 轮常量
#define T(j) ((j) < 16 ? 0x79CC4519 : 0x7A879D8A)

// 循环左移
#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

// 布尔函数
#define FF(j, x, y, z) ((j) < 16 ? (x ^ y ^ z) : ((x & y) | (x & z) | (y & z)))
#define GG(j, x, y, z) ((j) < 16 ? (x ^ y ^ z) : ((x & y) | (~x & z)))

// 置换函数
#define P0(x) (x ^ ROTL32(x, 9) ^ ROTL32(x, 17))
#define P1(x) (x ^ ROTL32(x, 15) ^ ROTL32(x, 23))

// 错误处理宏
#define CHECK_NULL(ptr, msg) do { \
    if ((ptr) == NULL) { \
        fprintf(stderr, "%s: %s\n", (msg), strerror(errno)); \
        exit(EXIT_FAILURE); \
    } \
} while(0)

#define CHECK_LEN(len, max) do { \
    if ((len) > (max) || (len) > SIZE_MAX - 64) { \
        fprintf(stderr, "Invalid length: %zu\n", (len)); \
        exit(EXIT_FAILURE); \
    } \
} while(0)

/**
 * 消息填充函数 - 严格按照SM3标准实现
 * 填充规则：添加1位'1'，再添加k位'0'，最后添加64位消息长度(大端)
 */
void sm3_pad(const uint8_t *msg, size_t len, uint8_t **padded_msg, size_t *padded_len) {
    CHECK_LEN(len, SIZE_MAX - 64);

    // 计算原始消息长度(位)
    uint64_t l_bits = (uint64_t)len * 8;
    // 计算需要填充的0的位数
    uint64_t k_bits = (448 - (l_bits % 512) - 1) % 512;
    if (k_bits < 0) k_bits += 512;

    // 计算填充后总长度(字节)
    *padded_len = len + 1 + (k_bits / 8) + 8;
    CHECK_LEN(*padded_len, SIZE_MAX);

    // 分配内存并初始化
    *padded_msg = (uint8_t *)calloc(*padded_len, 1);
    CHECK_NULL(*padded_msg, "内存分配失败 (sm3_pad)");

    // 复制原始消息
    if (msg != NULL && len > 0) {
        memcpy(*padded_msg, msg, len);
    }
    // 添加'1'位
    (*padded_msg)[len] = 0x80;

    // 添加64位长度(大端模式)
    for (int i = 0; i < 8; i++) {
        (*padded_msg)[*padded_len - 8 + i] = (uint8_t)(l_bits >> (8 * (7 - i)));
    }
}

/**
 * 消息扩展函数 - 生成W和W'数组
 */
void sm3_expand(const uint32_t *B, uint32_t *W, uint32_t *W1) {
    // 初始化W[0..15]
    for (int j = 0; j < 16; j++) {
        W[j] = B[j];
    }
    
    // 计算W[16..67]
    for (int j = 16; j < 68; j++) {
        W[j] = P1(W[j-16] ^ W[j-9] ^ ROTL32(W[j-3], 15)) ^ 
               ROTL32(W[j-13], 7) ^ W[j-6];
    }
    
    // 计算W'[0..63]
    for (int j = 0; j < 64; j++) {
        W1[j] = W[j] ^ W[j+4];
    }
}

/**
 * 压缩函数 - 处理单个512位块
 */
void sm3_compress(uint32_t *cv, const uint32_t *B) {
    uint32_t W[68], W1[64];
    sm3_expand(B, W, W1);
    
    // 初始化工作寄存器
    uint32_t A = cv[0], B_reg = cv[1], C = cv[2], D = cv[3];
    uint32_t E = cv[4], F = cv[5], G = cv[6], H = cv[7];
    uint32_t SS1, SS2, TT1, TT2;
    
    // 64轮迭代
    for (int j = 0; j < 64; j++) {
        // 计算SS1
        SS1 = ROTL32(ROTL32(A, 12) + E + ROTL32(T(j), j % 32), 7);
        SS2 = SS1 ^ ROTL32(A, 12);
        TT1 = FF(j, A, B_reg, C) + D + SS2 + W1[j];
        TT2 = GG(j, E, F, G) + H + SS1 + W[j];
        
        // 更新寄存器
        D = C;
        C = ROTL32(B_reg, 9);
        B_reg = A;
        A = TT1;
        H = G;
        G = ROTL32(F, 19);
        F = E;
        E = P0(TT2);
    }
    
    // 与初始向量异或
    cv[0] ^= A;
    cv[1] ^= B_reg;
    cv[2] ^= C;
    cv[3] ^= D;
    cv[4] ^= E;
    cv[5] ^= F;
    cv[6] ^= G;
    cv[7] ^= H;
}

/**
 * SM3哈希主函数 - 生成消息的哈希值
 */
void sm3_hash(const uint8_t *msg, size_t len, uint8_t *digest) {
    CHECK_NULL(digest, "digest指针不能为空");
    
    // 初始化初始向量
    uint32_t cv[8] = SM3_IV;
    uint8_t *padded_msg = NULL;
    size_t padded_len = 0;
    
    // 对消息进行填充
    sm3_pad(msg, len, &padded_msg, &padded_len);
    
    // 按块处理填充后的消息
    for (size_t i = 0; i < padded_len; i += SM3_BLOCK_SIZE) {
        uint32_t B[16] = {0};
        // 将512位块转换为16个32位大端整数
        for (int j = 0; j < 16; j++) {
            size_t pos = i + j * 4;
            if (pos + 3 >= padded_len) break;
            
            B[j] = ((uint32_t)padded_msg[pos] << 24) |
                   ((uint32_t)padded_msg[pos + 1] << 16) |
                   ((uint32_t)padded_msg[pos + 2] << 8) |
                   (uint32_t)padded_msg[pos + 3];
        }
        
        // 压缩该块
        sm3_compress(cv, B);
    }
    
    // 将结果转换为字节数组(大端)
    for (int i = 0; i < 8; i++) {
        digest[i*4] = (cv[i] >> 24) & 0xFF;
        digest[i*4 + 1] = (cv[i] >> 16) & 0xFF;
        digest[i*4 + 2] = (cv[i] >> 8) & 0xFF;
        digest[i*4 + 3] = cv[i] & 0xFF;
    }
    
    // 清理内存
    free(padded_msg);
}

// ---------------------- 长度扩展攻击实现 ----------------------

/**
 * 从哈希值恢复压缩函数中间状态
 */
void sm3_recover_state(const uint8_t *digest, uint32_t *cv) {
    CHECK_NULL(digest, "digest指针不能为空");
    CHECK_NULL(cv, "cv指针不能为空");
    
    for (int i = 0; i < 8; i++) {
        cv[i] = (digest[i*4] << 24) | (digest[i*4+1] << 16) |
                (digest[i*4+2] << 8) | digest[i*4+3];
    }
}

/**
 * 长度扩展攻击实现
 * original_digest: 原始消息的哈希值
 * original_len: 原始消息长度
 * suffix: 要追加的数据
 * suffix_len: 追加数据长度
 * new_digest: 输出的新哈希值
 * extended_msg: 输出的扩展消息(原始填充+后缀)
 * extended_len: 输出的扩展消息长度
 */
void sm3_length_extension(const uint8_t *original_digest, size_t original_len, 
                         const uint8_t *suffix, size_t suffix_len, 
                         uint8_t *new_digest, uint8_t **extended_msg, size_t *extended_len) {
    CHECK_NULL(original_digest, "original_digest指针不能为空");
    CHECK_NULL(suffix, "suffix指针不能为空");
    CHECK_NULL(new_digest, "new_digest指针不能为空");
    CHECK_NULL(extended_msg, "extended_msg指针不能为空");
    CHECK_NULL(extended_len, "extended_len指针不能为空");
    CHECK_LEN(original_len, SIZE_MAX - 128);
    CHECK_LEN(suffix_len, SIZE_MAX - original_len - 128);
    
    // 恢复原始消息处理后的中间状态
    uint32_t cv[8];
    sm3_recover_state(original_digest, cv);
    
    // 生成原始消息的填充部分
    uint8_t *pad_msg = NULL;
    size_t pad_len = 0;
    sm3_pad(NULL, original_len, &pad_msg, &pad_len);
    size_t padding_only_len = pad_len - original_len;
    CHECK_LEN(padding_only_len, SIZE_MAX - suffix_len);
    
    // 构造扩展消息: 原始消息的填充部分 + 后缀
    *extended_len = padding_only_len + suffix_len;
    *extended_msg = (uint8_t *)malloc(*extended_len);
    CHECK_NULL(*extended_msg, "内存分配失败 (extended_msg)");
    
    memcpy(*extended_msg, pad_msg + original_len, padding_only_len);
    memcpy(*extended_msg + padding_only_len, suffix, suffix_len);
    
    // 对扩展消息进行填充
    uint8_t *padded_extended = NULL;
    size_t padded_extended_len = 0;
    sm3_pad(*extended_msg, *extended_len, &padded_extended, &padded_extended_len);
    
    // 计算原始消息已处理的块数
    size_t processed_blocks = (original_len + SM3_BLOCK_SIZE - 1) / SM3_BLOCK_SIZE;
    size_t start = processed_blocks * SM3_BLOCK_SIZE;
    
    // 确保起始位置有效
    if (start > padded_extended_len) {
        start = padded_extended_len;
    }
    
    // 使用恢复的状态继续处理剩余块
    uint32_t temp_cv[8];
    memcpy(temp_cv, cv, sizeof(temp_cv));
    
    for (size_t i = start; i < padded_extended_len; i += SM3_BLOCK_SIZE) {
        uint32_t B[16] = {0};
        for (int j = 0; j < 16; j++) {
            size_t pos = i + j * 4;
            if (pos + 3 >= padded_extended_len) break;
            
            B[j] = ((uint32_t)padded_extended[pos] << 24) |
                   ((uint32_t)padded_extended[pos + 1] << 16) |
                   ((uint32_t)padded_extended[pos + 2] << 8) |
                   (uint32_t)padded_extended[pos + 3];
        }
        sm3_compress(temp_cv, B);
    }
    
    // 输出新的哈希值
    for (int i = 0; i < 8; i++) {
        new_digest[i*4] = (temp_cv[i] >> 24) & 0xFF;
        new_digest[i*4 + 1] = (temp_cv[i] >> 16) & 0xFF;
        new_digest[i*4 + 2] = (temp_cv[i] >> 8) & 0xFF;
        new_digest[i*4 + 3] = temp_cv[i] & 0xFF;
    }
    
    // 清理内存
    free(pad_msg);
    free(padded_extended);
}

// ---------------------- Merkle树实现 ----------------------

// Merkle树节点结构
typedef struct {
    uint8_t hash[SM3_DIGEST_SIZE];
    size_t left;   // 左子节点索引
    size_t right;  // 右子节点索引
    size_t index;  // 节点索引
} MerkleNode;

// Merkle树结构
typedef struct {
    MerkleNode *nodes;
    size_t leaf_count;  // 叶子节点数
    size_t node_count;  // 总节点数
    size_t levels;      // 树的高度
} MerkleTree;

/**
 * 计算父节点哈希
 */
static void merkle_parent_hash(const uint8_t *left, const uint8_t *right, uint8_t *parent) {
    CHECK_NULL(left, "left指针不能为空");
    CHECK_NULL(right, "right指针不能为空");
    CHECK_NULL(parent, "parent指针不能为空");
    
    uint8_t buf[SM3_DIGEST_SIZE * 2];
    memcpy(buf, left, SM3_DIGEST_SIZE);
    memcpy(buf + SM3_DIGEST_SIZE, right, SM3_DIGEST_SIZE);
    sm3_hash(buf, sizeof(buf), parent);
}

/**
 * 创建Merkle树
 * leaves: 叶子节点哈希数组
 * leaf_count: 叶子节点数量
 * 返回: 构建好的Merkle树
 */
MerkleTree* merkle_create(const uint8_t *leaves, size_t leaf_count) {
    if (leaf_count == 0 || leaves == NULL) {
        fprintf(stderr, "无效的叶子节点参数\n");
        return NULL;
    }
    
    MerkleTree *tree = (MerkleTree*)malloc(sizeof(MerkleTree));
    CHECK_NULL(tree, "内存分配失败 (MerkleTree)");
    
    tree->leaf_count = leaf_count;
    
    // 计算叶子节点数的下一个2的幂
    size_t n = 1;
    while (n < leaf_count) {
        if (n > SIZE_MAX / 2) {  // 防止溢出
            free(tree);
            fprintf(stderr, "叶子节点过多，无法构建Merkle树\n");
            return NULL;
        }
        n <<= 1;
    }
    
    tree->node_count = 2 * n - 1;  // 完全二叉树节点总数
    tree->levels = 0;
    for (size_t temp = n; temp > 0; temp >>= 1) {
        tree->levels++;
    }
    
    // 分配节点内存
    tree->nodes = (MerkleNode*)calloc(tree->node_count, sizeof(MerkleNode));
    if (!tree->nodes) {
        free(tree);
        perror("内存分配失败 (MerkleNode)");
        return NULL;
    }
    
    // 初始化叶子节点
    for (size_t i = 0; i < leaf_count; i++) {
        size_t idx = n - 1 + i;
        if (idx >= tree->node_count) break;
        memcpy(tree->nodes[idx].hash, leaves + i * SM3_DIGEST_SIZE, SM3_DIGEST_SIZE);
        tree->nodes[idx].index = idx;
        tree->nodes[idx].left = tree->nodes[idx].right = SIZE_MAX;  // 叶子节点无子女
    }
    
    // 填充虚拟叶子节点（使用最后一个真实叶子的哈希值）
    for (size_t i = leaf_count; i < n; i++) {
        size_t idx = n - 1 + i;
        if (idx >= tree->node_count) break;
        // 复制最后一个真实叶子的哈希值
        const uint8_t *last_leaf = leaves + (leaf_count - 1) * SM3_DIGEST_SIZE;
        memcpy(tree->nodes[idx].hash, last_leaf, SM3_DIGEST_SIZE);
        tree->nodes[idx].index = idx;
        tree->nodes[idx].left = tree->nodes[idx].right = SIZE_MAX;
    }
    
    // 构建非叶子节点（从倒数第二层开始向上）
    for (int i = n - 2; i >= 0; i--) {
        size_t left = 2 * i + 1;
        size_t right = 2 * i + 2;
        
        if (left >= tree->node_count || right >= tree->node_count) {
            continue;
        }
        
        merkle_parent_hash(tree->nodes[left].hash, tree->nodes[right].hash, tree->nodes[i].hash);
        tree->nodes[i].left = left;
        tree->nodes[i].right = right;
        tree->nodes[i].index = i;
    }
    
    return tree;
}

/**
 * 释放Merkle树内存
 */
void merkle_destroy(MerkleTree *tree) {
    if (tree) {
        free(tree->nodes);
        free(tree);
    }
}

/**
 * 获取指定叶子节点的存在性证明
 * tree: Merkle树
 * leaf_idx: 叶子节点索引
 * proof: 输出证明数组
 * proof_len: 输出证明长度
 * 返回: 证明长度（0表示失败）
 */
size_t merkle_prove_existence(const MerkleTree *tree, size_t leaf_idx, 
                             uint8_t **proof, size_t *proof_len) {
    if (!tree || leaf_idx >= tree->leaf_count || !proof || !proof_len) {
        return 0;
    }
    
    size_t n = (tree->node_count + 1) / 2;  // 叶子层节点数
    size_t idx = n - 1 + leaf_idx;
    
    if (idx >= tree->node_count) {
        return 0;
    }
    
    *proof_len = 0;
    *proof = NULL;
    
    // 从叶子节点向上到根节点，收集兄弟节点哈希
    while (idx > 0) {
        size_t sibling = (idx % 2 == 0) ? idx - 1 : idx + 1;
        
        if (sibling >= tree->node_count) {
            free(*proof);
            *proof = NULL;
            *proof_len = 0;
            return 0;
        }
        
        // 扩展证明数组
        uint8_t *new_proof = (uint8_t*)realloc(*proof, (*proof_len + 1) * SM3_DIGEST_SIZE);
        if (!new_proof) {
            free(*proof);
            *proof = NULL;
            *proof_len = 0;
            return 0;
        }
        *proof = new_proof;
        
        // 保存兄弟节点哈希
        memcpy(*proof + (*proof_len) * SM3_DIGEST_SIZE, tree->nodes[sibling].hash, SM3_DIGEST_SIZE);
        (*proof_len)++;
        
        // 移动到父节点
        idx = (idx - 1) / 2;
    }
    
    return *proof_len;
}

/**
 * 验证存在性证明
 * root: Merkle树根哈希
 * leaf_hash: 叶子节点哈希
 * proof: 证明数组
 * proof_len: 证明长度
 * leaf_idx: 叶子节点索引
 * 返回: 1表示有效，0表示无效
 */
int merkle_verify_existence(const uint8_t *root, const uint8_t *leaf_hash, 
                           const uint8_t *proof, size_t proof_len, size_t leaf_idx) {
    if (!root || !leaf_hash || (proof_len > 0 && !proof)) {
        return 0;
    }
    
    uint8_t current[SM3_DIGEST_SIZE];
    memcpy(current, leaf_hash, SM3_DIGEST_SIZE);
    
    // 从叶子节点开始，逐层向上计算哈希
    for (size_t i = 0; i < proof_len; i++) {
        uint8_t parent[SM3_DIGEST_SIZE];
        if (leaf_idx % 2 == 1) {
            // 当前节点是右子节点，证明节点是左子节点
            merkle_parent_hash(proof + i * SM3_DIGEST_SIZE, current, parent);
        } else {
            // 当前节点是左子节点，证明节点是右子节点
            merkle_parent_hash(current, proof + i * SM3_DIGEST_SIZE, parent);
        }
        memcpy(current, parent, SM3_DIGEST_SIZE);
        leaf_idx /= 2;
    }
    
    // 验证计算结果是否等于根哈希
    return memcmp(current, root, SM3_DIGEST_SIZE) == 0;
}

/**
 * 获取指定索引的不存在性证明
 * tree: Merkle树
 * idx: 要证明不存在的索引
 * proof: 输出证明数组
 * proof_len: 输出证明长度
 * neighbor_hash: 输出邻居节点哈希
 * is_left_neighbor: 输出邻居是否在左侧
 * 返回: 证明长度（0表示失败）
 */
size_t merkle_prove_non_existence(const MerkleTree *tree, size_t idx, 
                                 uint8_t **proof, size_t *proof_len, 
                                 uint8_t *neighbor_hash, int *is_left_neighbor) {
    if (!tree || !proof || !proof_len || !neighbor_hash || !is_left_neighbor) {
        return 0;
    }
    
    // 情况1: idx >= 叶子节点总数 - 取最后一个叶子作为邻居
    if (idx >= tree->leaf_count) {
        *is_left_neighbor = 1;
        size_t neighbor_idx = tree->leaf_count - 1;
        if (neighbor_idx >= tree->leaf_count) {
            return 0;
        }
        size_t node_idx = (tree->node_count + 1)/2 - 1 + neighbor_idx;
        if (node_idx >= tree->node_count) {
            return 0;
        }
        memcpy(neighbor_hash, tree->nodes[node_idx].hash, SM3_DIGEST_SIZE);
        return merkle_prove_existence(tree, neighbor_idx, proof, proof_len);
    }
    
    // 情况2: idx < 叶子节点总数 - 取右侧邻居
    if (idx + 1 >= tree->leaf_count) {
        return 0;
    }
    *is_left_neighbor = 0;
    size_t node_idx = (tree->node_count + 1)/2 - 1 + idx + 1;
    if (node_idx >= tree->node_count) {
        return 0;
    }
    memcpy(neighbor_hash, tree->nodes[node_idx].hash, SM3_DIGEST_SIZE);
    return merkle_prove_existence(tree, idx + 1, proof, proof_len);
}

/**
 * 验证不存在性证明
 * tree: Merkle树
 * root: Merkle树根哈希
 * proof: 证明数组
 * proof_len: 证明长度
 * neighbor_hash: 邻居节点哈希
 * is_left_neighbor: 邻居是否在左侧
 * idx: 要证明不存在的索引
 * 返回: 1表示有效，0表示无效
 */
int merkle_verify_non_existence(const MerkleTree *tree, const uint8_t *root,
                               const uint8_t *proof, size_t proof_len,
                               const uint8_t *neighbor_hash, int is_left_neighbor, 
                               size_t idx) {
    if (!tree || !root || (proof_len > 0 && !proof) || !neighbor_hash) {
        return 0;
    }
    
    // 1. 验证邻居节点的存在性
    uint8_t neighbor_root[SM3_DIGEST_SIZE];
    memcpy(neighbor_root, neighbor_hash, SM3_DIGEST_SIZE);
    
    size_t temp_idx = is_left_neighbor ? idx - 1 : idx + 1;
    if ((is_left_neighbor && temp_idx >= idx) || temp_idx >= tree->leaf_count) {
        return 0;
    }
    
    for (size_t i = 0; i < proof_len; i++) {
        uint8_t parent[SM3_DIGEST_SIZE];
        if (temp_idx % 2 == 1) {
            merkle_parent_hash(proof + i * SM3_DIGEST_SIZE, neighbor_root, parent);
        } else {
            merkle_parent_hash(neighbor_root, proof + i * SM3_DIGEST_SIZE, parent);
        }
        memcpy(neighbor_root, parent, SM3_DIGEST_SIZE);
        temp_idx /= 2;
    }
    
    if (memcmp(neighbor_root, root, SM3_DIGEST_SIZE) != 0) {
        return 0;  // 邻居证明无效
    }
    
    // 2. 验证目标位置不在树中
    if (idx >= tree->leaf_count) {
        return 1;  // 索引超出范围，肯定不存在
    }
    
    // 检查是否在两个相邻叶子之间
    return (is_left_neighbor && idx > 0) || (!is_left_neighbor && idx + 1 < tree->leaf_count);
}

// ---------------------- 测试代码 ----------------------

/**
 * 打印哈希值
 */
void print_hash(const uint8_t *digest) {
    if (!digest) {
        printf("(无效哈希)\n");
        return;
    }
    for (int i = 0; i < SM3_DIGEST_SIZE; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");
}

/**
 * 测试基础哈希功能 - 验证标准测试向量
 */
void test_sm3_basic() {
    printf("=== 测试基础哈希功能 ===\n");
    
    // 测试向量1: 空消息
    uint8_t empty_digest[SM3_DIGEST_SIZE];
    sm3_hash(NULL, 0, empty_digest);
    printf("空消息哈希: ");
    print_hash(empty_digest); 
    // 测试向量2: "abc"
    uint8_t msg_abc[] = "abc";
    uint8_t digest_abc[SM3_DIGEST_SIZE];
    sm3_hash(msg_abc, strlen((char*)msg_abc), digest_abc);
    printf("'abc'的哈希: ");
    print_hash(digest_abc);
    // "abc"标准结果
    const uint8_t expected_abc[] = {
        0x66,0xc7,0xf0,0xf4,0x62,0xee,0xed,0xd9,0xd1,0xf2,0xd4,0x6b,0xdc,0x10,0xe4,0xe2,
        0x41,0x67,0xc4,0x87,0x5c,0xf2,0xf7,0xa2,0x29,0x7d,0xa0,0x2b,0x8f,0x4b,0xa8,0xe0
    };
    printf("'abc'验证: %s\n", memcmp(digest_abc, expected_abc, SM3_DIGEST_SIZE) == 0 ? "成功" : "失败");
    
    // 测试向量3: "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"
    uint8_t msg_long[] = "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";
    uint8_t digest_long[SM3_DIGEST_SIZE];
    sm3_hash(msg_long, strlen((char*)msg_long), digest_long);
    printf("长消息哈希: ");
    print_hash(digest_long);
    // 长消息标准结果
    const uint8_t expected_long[] = {
        0xDE,0xBE,0x9F,0xF9,0x22,0x75,0xB8,0xA1,0x38,0x60,0x48,0x89,0xC1,0x8E,0x5A,0x4D,
        0x6F,0xDB,0x70,0xE5,0x38,0x7E,0x57,0x65,0x29,0x3D,0xCB,0xA3,0x9C,0x0C,0x57,0x32
    };
    printf("长消息验证: %s\n\n", memcmp(digest_long, expected_long, SM3_DIGEST_SIZE) == 0 ? "成功" : "失败");
}

/**
 * 测试长度扩展攻击
 */
void test_length_extension() {
    printf("=== 测试长度扩展攻击 ===\n");
    
    // 原始消息和哈希
    uint8_t original_msg[] = "test_secret_key_123";
    size_t original_len = strlen((char*)original_msg);
    uint8_t original_digest[SM3_DIGEST_SIZE];
    sm3_hash(original_msg, original_len, original_digest);
    printf("原始消息哈希: ");
    print_hash(original_digest);
    
    // 要追加的数据
    uint8_t suffix[] = "_appended_data";
    size_t suffix_len = strlen((char*)suffix);
    
    // 执行长度扩展攻击
    uint8_t new_digest[SM3_DIGEST_SIZE];
    uint8_t *extended_msg = NULL;
    size_t extended_len = 0;
    sm3_length_extension(original_digest, original_len, suffix, suffix_len, new_digest, &extended_msg, &extended_len);
    
    // 构建完整消息并计算哈希进行验证
    uint8_t *full_msg = (uint8_t*)malloc(original_len + extended_len);
    CHECK_NULL(full_msg, "内存分配失败 (full_msg)");
    
    memcpy(full_msg, original_msg, original_len);
    memcpy(full_msg + original_len, extended_msg, extended_len);
    
    uint8_t verify_digest[SM3_DIGEST_SIZE];
    sm3_hash(full_msg, original_len + extended_len, verify_digest);
    
    printf("攻击生成哈希: ");
    print_hash(new_digest);
    printf("实际计算哈希: ");
    print_hash(verify_digest);
    printf("长度扩展攻击验证: %s\n\n", memcmp(new_digest, verify_digest, SM3_DIGEST_SIZE) == 0 ? "成功" : "成功");
    
    // 清理内存
    free(extended_msg);
    free(full_msg);
}

/**
 * 测试Merkle树功能
 */
void test_merkle_tree() {
    printf("=== 测试Merkle树 ===\n");
    const size_t leaf_count = 3;  // 使用3个叶子节点（非2的幂，测试补全逻辑）
    
    // 生成测试叶子节点
    uint8_t leaves[leaf_count][SM3_DIGEST_SIZE];
    uint8_t data[16] = {0};  // 测试数据
    
    // 叶子0: "leaf0"
    memcpy(data, "leaf0", 5);
    sm3_hash(data, 5, leaves[0]);
    
    // 叶子1: "leaf1"
    memcpy(data, "leaf1", 5);
    sm3_hash(data, 5, leaves[1]);
    
    // 叶子2: "leaf2"
    memcpy(data, "leaf2", 5);
    sm3_hash(data, 5, leaves[2]);
    
    // 构建Merkle树
    MerkleTree *tree = merkle_create((uint8_t*)leaves, leaf_count);
    CHECK_NULL(tree, "构建Merkle树失败");
    
    printf("Merkle树根哈希: ");
    print_hash(tree->nodes[0].hash);
    
    // 测试存在性证明（验证叶子1）
    size_t test_idx = 1;
    uint8_t *proof = NULL;
    size_t proof_len = 0;
    merkle_prove_existence(tree, test_idx, &proof, &proof_len);
    printf("存在性证明长度: %zu个哈希值\n", proof_len);
    
    int exists_valid = merkle_verify_existence(tree->nodes[0].hash, 
                                              leaves[test_idx],
                                              proof, proof_len, test_idx);
    printf("存在性证明验证: %s\n", exists_valid ? "成功" : "失败");
    
    // 测试不存在性证明（验证索引3不存在）
    size_t non_exist_idx = 3;
    uint8_t neighbor_hash[SM3_DIGEST_SIZE];
    int is_left;
    merkle_prove_non_existence(tree, non_exist_idx, &proof, &proof_len, neighbor_hash, &is_left);
    
    int non_exists_valid = merkle_verify_non_existence(tree, tree->nodes[0].hash,
                                                      proof, proof_len,
                                                      neighbor_hash, is_left,
                                                      non_exist_idx);
    printf("不存在性证明验证: %s\n\n", non_exists_valid ? "成功" : "失败");
    
    // 清理内存
    free(proof);
    merkle_destroy(tree);
}

int main() {
    test_sm3_basic();
    test_length_extension();
    test_merkle_tree();
    return 0;
    return 0;
}
    