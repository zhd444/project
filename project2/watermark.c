#define STB_IMAGE_IMPLEMENTATION
#include "stb_image.h"
#define STB_IMAGE_WRITE_IMPLEMENTATION
#include "stb_image_write.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

// 水印参数
#define WATERMARK_WIDTH 32
#define WATERMARK_HEIGHT 32
#define ALPHA 0.1f  // 水印强度因子

// 生成简单二进制水印(32x32)
void generate_watermark(unsigned char watermark[WATERMARK_HEIGHT][WATERMARK_WIDTH]) {
    // 生成棋盘格图案作为示例水印
    for (int i = 0; i < WATERMARK_HEIGHT; i++) {
        for (int j = 0; j < WATERMARK_WIDTH; j++) {
            watermark[i][j] = ((i/4 + j/4) % 2) ? 255 : 0;
        }
    }
}

// 嵌入水印到图片的LSB位
void embed_watermark(const char *input_path, const char *output_path, 
                    unsigned char watermark[WATERMARK_HEIGHT][WATERMARK_WIDTH]) {
    int width, height, channels;
    unsigned char *image = stbi_load(input_path, &width, &height, &channels, 0);
    if (!image) {
        printf("无法加载图片: %s\n", input_path);
        return;
    }

    // 确保图片尺寸不小于水印
    if (width < WATERMARK_WIDTH || height < WATERMARK_HEIGHT) {
        printf("图片尺寸小于水印尺寸\n");
        stbi_image_free(image);
        return;
    }

    // 嵌入水印到蓝通道的最低位
    for (int i = 0; i < WATERMARK_HEIGHT; i++) {
        for (int j = 0; j < WATERMARK_WIDTH; j++) {
            int pos = (i * width + j) * channels + 2;  // 蓝通道位置
            // 清除最低位，嵌入水印位
            image[pos] = (image[pos] & 0xFE) | (watermark[i][j] ? 1 : 0);
        }
    }

    // 保存带水印的图片
    stbi_write_png(output_path, width, height, channels, image, width * channels);
    stbi_image_free(image);
    printf("水印嵌入完成: %s\n", output_path);
}

// 从图片中提取水印
void extract_watermark(const char *input_path, unsigned char watermark[WATERMARK_HEIGHT][WATERMARK_WIDTH]) {
    int width, height, channels;
    unsigned char *image = stbi_load(input_path, &width, &height, &channels, 0);
    if (!image) {
        printf("无法加载图片: %s\n", input_path);
        return;
    }

    // 提取水印
    for (int i = 0; i < WATERMARK_HEIGHT; i++) {
        for (int j = 0; j < WATERMARK_WIDTH; j++) {
            if (i >= height || j >= width) {
                watermark[i][j] = 0;
                continue;
            }
            int pos = (i * width + j) * channels + 2;  // 蓝通道位置
            watermark[i][j] = (image[pos] & 1) ? 255 : 0;  // 提取最低位
        }
    }

    stbi_image_free(image);
    printf("水印提取完成\n");
}

// 图片处理：翻转
void flip_image(const char *input_path, const char *output_path, int horizontal) {
    int width, height, channels;
    unsigned char *image = stbi_load(input_path, &width, &height, &channels, 0);
    if (!image) return;

    unsigned char *flipped = malloc(width * height * channels);
    for (int i = 0; i < height; i++) {
        for (int j = 0; j < width; j++) {
            int src_x = horizontal ? (width - 1 - j) : j;
            int src_y = horizontal ? i : (height - 1 - i);
            int src_pos = (src_y * width + src_x) * channels;
            int dst_pos = (i * width + j) * channels;
            memcpy(&flipped[dst_pos], &image[src_pos], channels);
        }
    }

    stbi_write_png(output_path, width, height, channels, flipped, width * channels);
    free(flipped);
    stbi_image_free(image);
}

// 图片处理：调整对比度
void adjust_contrast(const char *input_path, const char *output_path, float factor) {
    int width, height, channels;
    unsigned char *image = stbi_load(input_path, &width, &height, &channels, 0);
    if (!image) return;

    for (int i = 0; i < width * height * channels; i++) {
        float val = image[i] / 255.0f;
        val = (val - 0.5f) * factor + 0.5f;  // 对比度调整公式
        val = val < 0 ? 0 : (val > 1 ? 1 : val);
        image[i] = (unsigned char)(val * 255);
    }

    stbi_write_png(output_path, width, height, channels, image, width * channels);
    stbi_image_free(image);
}

// 计算水印相似度（归一化互相关）
float calculate_similarity(unsigned char orig[WATERMARK_HEIGHT][WATERMARK_WIDTH],
                          unsigned char extracted[WATERMARK_HEIGHT][WATERMARK_WIDTH]) {
    int same = 0, total = 0;
    for (int i = 0; i < WATERMARK_HEIGHT; i++) {
        for (int j = 0; j < WATERMARK_WIDTH; j++) {
            if ((orig[i][j] && extracted[i][j]) || (!orig[i][j] && !extracted[i][j])) {
                same++;
            }
            total++;
        }
    }
    return (float)same / total;
}

// 保存提取的水印为图片
void save_watermark_image(const char *path, unsigned char watermark[WATERMARK_HEIGHT][WATERMARK_WIDTH]) {
    unsigned char *img = malloc(WATERMARK_WIDTH * WATERMARK_HEIGHT * 3);
    for (int i = 0; i < WATERMARK_HEIGHT; i++) {
        for (int j = 0; j < WATERMARK_WIDTH; j++) {
            int pos = (i * WATERMARK_WIDTH + j) * 3;
            img[pos] = img[pos+1] = img[pos+2] = watermark[i][j];
        }
    }
    stbi_write_png(path, WATERMARK_WIDTH, WATERMARK_HEIGHT, 3, img, WATERMARK_WIDTH * 3);
    free(img);
}

int main() {
    unsigned char orig_wm[WATERMARK_HEIGHT][WATERMARK_WIDTH];
    unsigned char extracted_wm[WATERMARK_HEIGHT][WATERMARK_WIDTH];
    
    // 生成原始水印
    generate_watermark(orig_wm);
    save_watermark_image("original_watermark.png", orig_wm);

    // 嵌入水印
    embed_watermark("input.png", "watermarked.png", orig_wm);

    // 鲁棒性测试：各种处理
    flip_image("watermarked.png", "flipped.png", 1);  // 水平翻转
    adjust_contrast("watermarked.png", "high_contrast.png", 1.5f);  // 高对比度
    // 可以添加更多测试：裁剪、旋转、压缩等

    // 从处理后的图片提取水印并测试相似度
    printf("\n=== 鲁棒性测试结果 ===\n");
    
    extract_watermark("watermarked.png", extracted_wm);
    save_watermark_image("extracted_original.png", extracted_wm);
    printf("原始带水印图片提取相似度: %.2f%%\n", 
           calculate_similarity(orig_wm, extracted_wm) * 100);

    extract_watermark("flipped.png", extracted_wm);
    save_watermark_image("extracted_flipped.png", extracted_wm);
    printf("翻转后提取相似度: %.2f%%\n", 
           calculate_similarity(orig_wm, extracted_wm) * 100);

    extract_watermark("high_contrast.png", extracted_wm);
    save_watermark_image("extracted_contrast.png", extracted_wm);
     printf("高对比度后提取相似度: %.2f%%\n", ​
           calculate_similarity(orig_wm, extracted_wm) * 100);

    return 0;
}