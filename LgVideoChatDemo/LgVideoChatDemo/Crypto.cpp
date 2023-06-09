#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <iostream>
#include "Crypto.h"


EVP_PKEY* GenerateRsaKey() {
    int ret = 0;
    EVP_PKEY* pkey = NULL;
    EVP_PKEY_CTX* ctx = NULL;

    int bits = 2048;
    int e = RSA_F4;

    // generate rsa key
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) {
        std::cerr << "Error during context creation" << std::endl;
        goto free_all;
    }

    ret = EVP_PKEY_keygen_init(ctx);
    if (ret != 1) {
        std::cerr << "Error during keygen init" << std::endl;
        goto free_all;
    }

    ret = EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits);
    if (ret != 1) {
        std::cerr << "Error setting keygen bits" << std::endl;
        goto free_all;
    }

    ret = EVP_PKEY_CTX_set1_rsa_keygen_pubexp(ctx, BN_new());
    if (ret != 1) {
        std::cerr << "Error setting keygen pubexp" << std::endl;
        goto free_all;
    }

    ret = EVP_PKEY_keygen(ctx, &pkey);
    if (ret != 1) {
        std::cerr << "Error during key generation" << std::endl;
        goto free_all;
    }

free_all:

    EVP_PKEY_CTX_free(ctx);

    return pkey;

}

void GenerateAesKey(unsigned char* aes_key, size_t aes_key_len) {
    if (!RAND_bytes(aes_key, aes_key_len)) {
        std::cerr << "Error during AES key generation" << std::endl;
    }
}

void RsaEncrypt(EVP_PKEY* pkey, const unsigned char* msg, size_t msg_len,
    unsigned char* encrypted_msg, size_t* encrypted_msg_len) {
    int ret = 0;
    EVP_PKEY_CTX* ctx = NULL;

    // encrypt msg with rsa public key
    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        std::cerr << "Error during context creation" << std::endl;
        goto free_all;
    }

    ret = EVP_PKEY_encrypt_init(ctx);
    if (ret != 1) {
        std::cerr << "Error during encrypt init" << std::endl;
        goto free_all;
    }

    ret = EVP_PKEY_encrypt(ctx, encrypted_msg, encrypted_msg_len,
        msg, msg_len);
    if (ret != 1) {
        std::cerr << "Error during encryption" << std::endl;
        goto free_all;
    }

free_all:

    EVP_PKEY_CTX_free(ctx);

}

void RsaDecrypt(EVP_PKEY* pkey, const unsigned char* msg, size_t msg_len,
    unsigned char* decrypted_msg, size_t* decrypted_msg_len) {
    int ret = 0;
    EVP_PKEY_CTX* ctx = NULL;

    // decrypt msg with rsa private key
    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        std::cerr << "Error during context creation" << std::endl;
        goto free_all;
    }

    ret = EVP_PKEY_decrypt_init(ctx);
    if (ret != 1) {
        std::cerr << "Error during decrypt init" << std::endl;
        goto free_all;
    }

    ret = EVP_PKEY_decrypt(ctx, decrypted_msg, decrypted_msg_len,
        msg, msg_len);
    if (ret != 1) {
        std::cerr << "Error during decryption" << std::endl;
        goto free_all;
    }

free_all:

    EVP_PKEY_CTX_free(ctx);

}

void AesEncrypt(const unsigned char* aes_key, size_t aes_key_len,
    const unsigned char* iv, size_t iv_len,
    const unsigned char* msg, size_t msg_len,
    unsigned char* encrypted_msg, size_t* encrypted_msg_len) {
    EVP_CIPHER_CTX* ctx = NULL;

    int len;

    int ret;

    // create and initialize the context
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        std::cerr << "Error during context creation" << std::endl;
        goto free_all;
    }

    // initialize the encryption operation
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, iv)) {
        std::cerr << "Error during encrypt init" << std::endl;
        goto free_all;
    }

    // provide the message to be encrypted, and obtain the encrypted output
    if (1 != EVP_EncryptUpdate(ctx, encrypted_msg, &len, msg, msg_len)) {
        std::cerr << "Error during encryption" << std::endl;
        goto free_all;
    }

    *encrypted_msg_len = len;

    // finalize the encryption
    if (1 != EVP_EncryptFinal_ex(ctx, encrypted_msg + len, &len)) {
        std::cerr << "Error during finalization of encryption" << std::endl;
        goto free_all;
    }

    *encrypted_msg_len += len;

free_all:

    EVP_CIPHER_CTX_free(ctx);

}

void AesDecrypt(const unsigned char* aes_key, size_t aes_key_len,
    const unsigned char* iv, size_t iv_len,
    const unsigned char* msg, size_t msg_len,
    unsigned char* decrypted_msg, size_t* decrypted_msg_len) {
    EVP_CIPHER_CTX* ctx = NULL;

    int len;

    int ret;

    // create and initialize the context
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        std::cerr << "Error during context creation" << std::endl;
        goto free_all;
    }

    // initialize the decryption operation
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, iv)) {
        std::cerr << "Error during decrypt init" << std::endl;
        goto free_all;
    }

    // provide the message to be decrypted, and obtain the decrypted output
    if (1 != EVP_DecryptUpdate(ctx, decrypted_msg, &len, msg, msg_len)) {
        std::cerr << "Error during decryption" << std::endl;
        goto free_all;
    }

    *decrypted_msg_len = len;

    // finalize the decryption
    if (1 != EVP_DecryptFinal_ex(ctx, decrypted_msg + len, &len)) {
        std::cerr << "Error during finalization of decryption" << std::endl;
        goto free_all;
    }

    *decrypted_msg_len += len;

free_all:

    EVP_CIPHER_CTX_free(ctx);

}

void CryptoTest() {
    EVP_PKEY* rsa_key = GenerateRsaKey();

    unsigned char aes_key[32];
    GenerateAesKey(aes_key, sizeof(aes_key));

    unsigned char encrypted_aes_key[256];
    size_t encrypted_aes_key_len;
    RsaEncrypt(rsa_key, aes_key, sizeof(aes_key),
        encrypted_aes_key, &encrypted_aes_key_len);

    unsigned char decrypted_aes_key[256];
    size_t decrypted_aes_key_len;
    RsaDecrypt(rsa_key, encrypted_aes_key, encrypted_aes_key_len,
        decrypted_aes_key, &decrypted_aes_key_len);

    const unsigned char* msg = (const unsigned char*)"Hello World!";
    size_t msg_len = strlen((const char*)msg);

    unsigned char iv[16] = { 0 };
    if (!RAND_bytes(iv, sizeof(iv))) {
        std::cerr << "Error during IV generation" << std::endl;
    }
    unsigned char encrypted_msg[1024];
    size_t encrypted_msg_len;
    AesEncrypt(aes_key, sizeof(aes_key), iv, sizeof(iv),
        msg, msg_len,
        encrypted_msg, &encrypted_msg_len);

    unsigned char decrypted_msg[1024];
    size_t decrypted_msg_len;
    AesDecrypt(aes_key, sizeof(aes_key), iv, sizeof(iv),
        encrypted_msg, encrypted_msg_len,
        decrypted_msg, &decrypted_msg_len);

    std::cout << "Original message: " << msg << std::endl;
    std::cout << "Decrypted message: " << decrypted_msg << std::endl;

    EVP_PKEY_free(rsa_key);
}
