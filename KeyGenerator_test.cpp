/* encoding: utf-8 */

// Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
// All rights reserved.

#include <cstdio>
//#include <cstdlib>
#include <cstring>
#include <cassert>
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
        const uint8_t key_data[], // 密钥内容
        size_t key_size, // 密钥长度
        const uint8_t data[], // 待加密的数据
        size_t data_size); // 待加密数据的长度
static void EncryptBinaryData(
        vector<uint8_t>& result, // 输出密文内容

        const EVP_CIPHER *cipher_algorithm, // 加密算法
        const vector<uint8_t>& key, // 包括密钥内容 key.data() 和密钥长度 key.size()
        const vector<uint8_t>& data); // 原始数据
static void EncryptString(
        vector<uint8_t>& result, // 输出密文内容

        const EVP_CIPHER *cipher_algorithm, // 加密算法
        const vector<uint8_t>& key, // 包括密钥内容 key.data() 和密钥长度 key.size()
        string msg); // 原始数据

/**
 * 解密函数
 */
static void Decrypt(
        string& result, // 输出明文内容, C++ string 内容不需要以'\0'结尾

        const EVP_CIPHER *cipher_algorithm, // 加解密算法
        const uint8_t key_data[], // 密钥内容
        size_t key_size, // 密钥长度
        vector<uint8_t> encrypted_msg); // 输入: 密文内容, 密文尾部包含若干填充字节padding

static void Decrypt(
        string& result, // 输出明文内容, C++ string 内容不需要以'\0'结尾

        const EVP_CIPHER *cipher_algorithm, // 加解密算法
        const vector<uint8_t>& key, // 包括密钥内容 key.data() 和密钥长度 key.size()
        vector<uint8_t> encrypted_msg); // 输入: 密文内容, 密文尾部包含若干填充字节padding

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
    vector<uint8_t> data(sizeof(msg));
    for (size_t i=0; i<data.size(); i++) {
        data[i] = msg[i];
    }
    if (debug) {
        printf("msg[]=\"%s\"\n", msg);
        printf("strlen(msg)=%d\n", strlen(msg));
        printf("data: ");
        for (size_t i=0; i<data.size(); i++) {
            printf("0x%02x,", data[i]);
        }
        printf("\n");
        printf("data.size()=%d\n", data.size());
    }

    vector<uint8_t> encrypted;

    EncryptBinaryData(encrypted, cipher, key, data);
    printf("After encryption, size=%d Bytes\n", encrypted.size());
    if (debug) {
        printf("encrypted: 0x%02x,", encrypted[0]);
        for (size_t i=1; i<encrypted.size(); i++) {
            printf("0x%02x,", encrypted[i]);
        }
        printf("\n");
    }
    string text;
    Decrypt(text, cipher, key, encrypted);
    printf("After Decrypt():\n");
    if (debug) {
        for (size_t i=0; i<text.size(); i++) {
            printf("0x%02x,", text[i]);
        }
        printf("\n");
        printf("msg[] %s text[]\n", (0 == memcmp((uint8_t *)msg, text.data(), sizeof(msg)))? "==": "!=");
    }

    return (0);
}

static void EraseSensitiveData(uint8_t data[], size_t length)
{
    memset(data, 0xFF, length);
}

static void Decrypt(
        string& result, // 输出明文内容, C++ string 内容不需要以'\0'结尾

        const EVP_CIPHER *cipher_algorithm, // 加解密算法
        const uint8_t key_data[], // 密钥内容
        size_t key_length, // 密钥长度, 取值一般应该等于 EVP_MAX_KEY_LENGTH
        vector<uint8_t> encrypted_msg) // 输入: 密文内容, 密文尾部包含若干填充字节padding
{
    EVP_CIPHER_CTX *ctx;

    ctx = EVP_CIPHER_CTX_new();

    uint8_t ivec[EVP_MAX_IV_LENGTH];

    memset(ivec, 0x00, EVP_MAX_IV_LENGTH);
    EVP_DecryptInit_ex(ctx, cipher_algorithm, (ENGINE *)NULL, key_data, ivec);
    assert(key_length > 0);

    const size_t BufferSize = encrypted_msg.size(); // 密文的长度通常是加密算法中定义的基本数据块大小的整数倍
    uint8_t *decrypted; // buffer

    decrypted = new uint8_t[BufferSize];

    int n;
    int result_length;

    result_length = 0;
    EVP_DecryptUpdate(ctx, decrypted, &n, encrypted_msg.data(),
            encrypted_msg.size());
    if (0) {
        printf("%s():line[%d]: n=%d\n", __func__, __LINE__, n);
    }
    result_length += n;
    assert((long long)result_length <= (long long) BufferSize);

    EVP_DecryptFinal_ex(ctx, decrypted + result_length, &n);
    if (0) {
        printf("%s():line[%d]: n=%d\n", __func__, __LINE__, n);
    }
    result_length += n;
    assert((long long)result_length <= (long long) BufferSize);

    /* 输出结果 */
    result.clear();
    result.assign((const char *)decrypted, result_length);

    /* 清理临时缓存的明文数据, 清理上下文中的密钥数据 */
    EraseSensitiveData(decrypted, result_length);
    delete[] decrypted;
    EVP_CIPHER_CTX_free(ctx);
    return;
}

static void Decrypt(
        string& result, // 输出明文内容

        const EVP_CIPHER *cipher_algorithm, // 加解密算法
        const vector<uint8_t>& key, // 包括密钥内容 key.data() 和密钥长度 key.size()
        vector<uint8_t> encrypted_msg) // 输入: 密文内容
{
    Decrypt(result, cipher_algorithm, key.data(), key.size(), encrypted_msg);
    return;
}

static void Encrypt(
        vector<uint8_t>& result, // 输出密文内容

        const EVP_CIPHER *cipher_algorithm, // 加密算法
        const uint8_t key_data[], // 密钥内容
        size_t key_size, // 密钥长度
        const uint8_t data[], // 待加密的数据
        size_t data_size) // 待加密数据的长度
{
    EVP_CIPHER_CTX *ctx;

    ctx = EVP_CIPHER_CTX_new();

    uint8_t ivec[EVP_MAX_IV_LENGTH];

    memset(ivec, 0x00, EVP_MAX_IV_LENGTH);
    EVP_EncryptInit(ctx, cipher_algorithm, key_data, ivec);

    uint8_t *encrypted;
    encrypted = new uint8_t[data_size + EVP_CIPHER_block_size(cipher_algorithm)];
//EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *out_length, unsigned char *in, int in_length);
//该函数执行对数据的加密。
//该函数加密从参数in输入的长度为inl的数据，并将加密好的数据写入到参数out里面去。
//可以通过反复调用该函数来处理一个连续的数据块。
//写入到out的数据数量是由已经加密的数据的对齐关系决定的，理论上来说，out_length从0到(in_length+cipher_block_size)的任何一个数字都有可能（单位是字节），所以输出的参数out要有足够的空间存储数据。
//写入到out中的实际数据长度保存在 out_length 参数中。
//操作成功返回1，否则返回0。
    int n;
    int offset;
    int padding_size;

    EVP_EncryptUpdate(ctx, encrypted, &n, data, data_size);
    offset = n;

    EVP_EncryptFinal(ctx, encrypted+offset, &n);
    offset += n;
    padding_size = n;
    if (0) {
        printf("padding_size=%d\n", padding_size);
    }
    result = std::vector<uint8_t>(encrypted, encrypted+data_size+padding_size);
    delete[] encrypted;
    EVP_CIPHER_CTX_free(ctx);
    return;
}

static void EncryptString(
        vector<uint8_t>& result, // 输出密文内容

        const EVP_CIPHER *cipher_algorithm, // 加密算法
        const vector<uint8_t>& key, // 包括密钥内容 key.data() 和密钥长度 key.size()
        string msg) // 原始数据
{
    Encrypt(result, cipher_algorithm, key.data(), key.size(), (const uint8_t *) msg.data(), msg.size());
    /* 清除原始明文文本数据的副本 */
    msg.assign(msg.size(), (char) '\0');
    msg.clear();
}
static void EncryptBinaryData(
        vector<uint8_t>& result, // 输出密文内容

        const EVP_CIPHER *cipher_algorithm, // 加密算法
        const vector<uint8_t>& key, // 包括密钥内容 key.data() 和密钥长度 key.size()
        const vector<uint8_t>& source) // 原始数据
{
    Encrypt(result, cipher_algorithm, key.data(), key.size(), source.data(), source.size());
    return;
}

static void Debug_MessageEncrypt(const EVP_CIPHER *cipher, const uint8_t key_data[], size_t key_length, const uint8_t msg[], size_t msg_length)
{
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();

    uint8_t ivec[EVP_MAX_IV_LENGTH];

    memset(ivec, 0x00, EVP_MAX_IV_LENGTH);
    EVP_EncryptInit(ctx, cipher, key_data, ivec);

    uint8_t *msg_encrypted;
    msg_encrypted = new uint8_t[msg_length + key_length];

    int left; // 剩余待加密字节数
    left = msg_length;
    int offset;
    offset = 0;
    while (left > 0) {
        int n;

        EVP_EncryptUpdate(ctx, msg_encrypted+offset, &n, (uint8_t *)msg+offset, left);
        offset += n;
        left -= n;
    }
    int padding_len;
    EVP_EncryptFinal(ctx, msg_encrypted+offset, &padding_len);

    printf("padding_len=%d\n", padding_len);
    const int n = msg_length + padding_len;
    printf("msg_encrypted: 0x%02x,", msg_encrypted[0]);
    for (int i=1; i<n; i++) {
        printf("0x%02x,", msg_encrypted[i]);
    }
    printf("\n");

    delete[] msg_encrypted;
    EVP_CIPHER_CTX_free(ctx);
    return;
}

// vim: tabstop=4:shiftwidth=4:expandtab
