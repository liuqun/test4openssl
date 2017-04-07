/* encoding: utf-8 */

// Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
// All rights reserved.

#include <cstdio>
//#include <cstdlib>
#include <cstring>
#include <openssl/evp.h>
#include <time.h>
#include <stdint.h>
#include <vector>
#include <string>
using namespace std;

/* 排版格式: 以下函数均使用4个空格缩进，不使用Tab缩进 */

extern "C" {

/**
 * 自定义函数
 */
static
void Debug_MessageEncrypt(const EVP_CIPHER *cipher, const uint8_t key_data[], size_t key_length, const uint8_t msg[], size_t msg_length);

}

/**
 * 加密函数
 */
static void Encrypt(
        vector<uint8_t>& result, // 输出密文内容

        const EVP_CIPHER *cipher_algorithm, // 加密算法
        vector<uint8_t> key, // 包括密钥内容 key.data() 和密钥长度 key.size()
        string msg); // 原始数据

int main(int argc, char *argv[])
{
    const int debug = (argc == 1); // 默认没有命令行参数时在调试模式下运行本程序
    time_t seed;

    seed = time(NULL);
    if (debug) {
        seed = 0;
        printf("Debug message: 随机数种子 seed=0x%X\n", (unsigned int) seed);
    }
    srand(seed);
    vector<uint8_t> key(EVP_MAX_KEY_LENGTH);
    printf("Debug message: key.size()=%d\n", key.size());
    for (size_t i=0; i<key.size(); i++) {
        key[i] = rand();
    }
    if (debug) {
        uint8_t *p;
        p = key.data();
        const uint8_t * const END_OF_KEY = key.data() + key.size();

        printf("Debug message: 密钥内容为敏感数据, 仅在调试模式下可以打印密钥内容\n");
        printf("key.data()={0x%02x,", *p++);
        while (p < END_OF_KEY) {
            printf("0x%02x,", *p++);
        }
        printf("}\nkey.size()=%d\n", key.size());
    }

    const EVP_CIPHER *Cipher_Blowfish_CBC = EVP_bf_cbc();
    const EVP_CIPHER *cipher = Cipher_Blowfish_CBC;
    const char msg[] = "This is a plain message for test";
    if (debug) {
        printf("msg[]=\"%s\"\n", msg);
        printf("strlen(msg)=%d\n", strlen(msg));
    }

    Debug_MessageEncrypt(cipher, key.data(), key.size(), (const uint8_t *) msg, strlen(msg));

    vector<uint8_t> encrypted;

    Encrypt(encrypted, cipher, key, msg);
    if (debug) {
        printf("encrypted: 0x%02x,", encrypted[0]);
        for (size_t i=1; i<encrypted.size(); i++) {
            printf("0x%02x,", encrypted[i]);
        }
        printf("\n");
    }

    return (0);
}

static void Encrypt(
        vector<uint8_t>& result, // 输出密文内容

        const EVP_CIPHER *cipher_algorithm, // 加密算法
        vector<uint8_t> key, // 包括密钥内容 key.data() 和密钥长度 key.size()
        string msg) // 原始数据
{
    EVP_CIPHER_CTX context;

    EVP_CIPHER_CTX_init(&context);

    uint8_t ivec[EVP_MAX_IV_LENGTH];

    memset(ivec, 0x00, EVP_MAX_IV_LENGTH);
    EVP_EncryptInit(&context, cipher_algorithm, key.data(), ivec);

    uint8_t *msg_encrypted;
    msg_encrypted = new uint8_t[msg.size() + key.size()];

    int left; // 剩余待加密字节数
    left = msg.size();
    int offset;
    offset = 0;
    while (left > 0) {
        int n;

        EVP_EncryptUpdate(&context, msg_encrypted+offset, &n, (uint8_t *)msg.data()+offset, left);
        offset += n;
        left -= n;
    }
    int padding_size;
    EVP_EncryptFinal(&context, msg_encrypted+offset, &padding_size);
    if (0) {
        printf("padding_size=%d\n", padding_size);
    }
    const int n = msg.size() + padding_size;
    result = std::vector<uint8_t>(msg_encrypted, msg_encrypted+n);
    delete[] msg_encrypted;
    EVP_CIPHER_CTX_cleanup(&context);
    return;
}

static void Debug_MessageEncrypt(const EVP_CIPHER *cipher, const uint8_t key_data[], size_t key_length, const uint8_t msg[], size_t msg_length)
{
    EVP_CIPHER_CTX context;
    EVP_CIPHER_CTX_init(&context);

    uint8_t ivec[EVP_MAX_IV_LENGTH];

    memset(ivec, 0x00, EVP_MAX_IV_LENGTH);
    EVP_EncryptInit(&context, cipher, key_data, ivec);

    uint8_t *msg_encrypted;
    msg_encrypted = new uint8_t[msg_length + key_length];

    int left; // 剩余待加密字节数
    left = msg_length;
    int offset;
    offset = 0;
    while (left > 0) {
        int n;

        EVP_EncryptUpdate(&context, msg_encrypted+offset, &n, (uint8_t *)msg+offset, left);
        offset += n;
        left -= n;
    }
    int padding_len;
    EVP_EncryptFinal(&context, msg_encrypted+offset, &padding_len);

    printf("padding_len=%d\n", padding_len);
    const int n = msg_length + padding_len;
    printf("msg_encrypted: 0x%02x,", msg_encrypted[0]);
    for (int i=1; i<n; i++) {
        printf("0x%02x,", msg_encrypted[i]);
    }
    printf("\n");

    delete[] msg_encrypted;
    EVP_CIPHER_CTX_cleanup(&context);
    return;
}

// vim: tabstop=4:shiftwidth=4:expandtab
