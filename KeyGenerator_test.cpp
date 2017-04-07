/* encoding: utf-8 */

// Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
// All rights reserved.

#include <cstdio>
//#include <cstdlib>
#include <cstring>
#include <openssl/evp.h>
#include <time.h>
#include <stdint.h>
using namespace std;

/* 排版格式: 以下函数均使用4个空格缩进，不使用Tab缩进 */

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
    struct {
        int length;
        uint8_t data[EVP_MAX_KEY_LENGTH];
        uint8_t END_OF_KEY;
    } key;
    key.length = sizeof(key.data);
    for (int i=0; i<key.length; i++) {
        key.data[i] = rand();
    }
    if (debug) {
        uint8_t *p;
        p = key.data;
        printf("Debug message: 密钥内容为敏感数据, 仅在调试模式下可以打印密钥内容\n");
        printf("key.data[]={0x%02x,", *p++);
        while (p < &(key.END_OF_KEY)) {
            printf("0x%02x,", *p++);
        }
        printf("}\nkey.length=%d\n", key.length);
    }
    EVP_CIPHER_CTX context;
    const EVP_CIPHER *Cipher_Blowfish_CBC = EVP_bf_cbc();
    const EVP_CIPHER *cipher = Cipher_Blowfish_CBC;
    uint8_t ivec[EVP_MAX_IV_LENGTH];
    memset(ivec, 0x00, EVP_MAX_IV_LENGTH);
    EVP_EncryptInit(&context, cipher, key.data, ivec);
    const char msg[] = "This is a plain message for test";
    uint8_t *msg_encrypted;
    msg_encrypted = new uint8_t[strlen(msg) + key.length];
    int left; // 剩余待加密字节数
    left = strlen(msg);
    int offset;
    offset = 0;
    while (left > 0) {
        int n;

        EVP_EncryptUpdate(&context, msg_encrypted+offset, &n, (uint8_t *)msg+offset, left);
        offset += n;
        left -= n;
    }
    int tail_len;
    EVP_EncryptFinal(&context, msg_encrypted+offset, &tail_len);
    if (debug) {
        printf("msg[]=\"%s\"\n", msg);
        printf("strlen(msg)=%d\n", strlen(msg));
        printf("tail_len=%d\n", tail_len);
        const int n = strlen(msg) + tail_len;
        printf("msg_encrypted: 0x%02x,", msg_encrypted[0]);
        for (int i=1; i<n; i++) {
            printf("0x%02x,", msg_encrypted[i]);
        }
        printf("\n");
    }
    delete[] msg_encrypted;
    if (debug) {
    }
    return (0);
}

// vim: tabstop=4:shiftwidth=4:expandtab
