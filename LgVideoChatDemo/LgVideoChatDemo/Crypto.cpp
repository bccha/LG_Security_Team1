#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <iostream>
#include "Crypto.h"

#define BUFFER_SIZE 64*1024
#define IV_SIZE 16

std::string g_recieved_rsa_pub_key;
std::string g_rsa_pub_key;
EVP_PKEY* g_rsa_key;
unsigned char g_aes_key[32];

EVP_PKEY* GenerateRsaKey(std::string& pubkey) {
    int ret = 0;
    EVP_PKEY* pkey = NULL;
    EVP_PKEY_CTX* ctx = NULL;
    BIO* publicBio = NULL;
    BIGNUM* e = NULL;
    int publicKeyLen = 0;

    int bits = 2048;

    // generate rsa key
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) {
        std::cout << "Error during context creation" << std::endl;
        goto free_all;
    }

    ret = EVP_PKEY_keygen_init(ctx);
    if (ret != 1) {
        std::cout << "Error during keygen init" << std::endl;
        goto free_all;
    }

    ret = EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits);
    if (ret != 1) {
        std::cout << "Error setting keygen bits" << std::endl;
        goto free_all;
    }

    e = BN_new();
    BN_set_word(e, RSA_F4);
    EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, EVP_PKEY_OP_KEYGEN, EVP_PKEY_CTRL_RSA_KEYGEN_PUBEXP, 0, e);

    ret = EVP_PKEY_keygen(ctx, &pkey);
    if (ret != 1) {
        std::cout << "Error during key generation" << std::endl;
        goto free_all;
    }

    publicBio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(publicBio, pkey);
    publicKeyLen = BIO_pending(publicBio);
    pubkey.resize(publicKeyLen);
    BIO_read(publicBio, &pubkey[0], publicKeyLen);
free_all:

    EVP_PKEY_CTX_free(ctx);

    return pkey;

}

void GenerateAesKey(unsigned char* aes_key, size_t aes_key_len) {
    if (!RAND_bytes(aes_key, aes_key_len)) {
        std::cout << "Error during AES key generation" << std::endl;
    }
}

void RsaEncrypt(EVP_PKEY* pkey, const unsigned char* msg, size_t msg_len,
    unsigned char* encrypted_msg, size_t* encrypted_msg_len) {
    int ret = 0;
    EVP_PKEY_CTX* ctx = NULL;
    size_t encryptedLen = 0;
    std::cout << "RsaEncrypt" << std::endl;
    // encrypt msg with rsa public key
    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        std::cout << "Error during context creation" << std::endl;
        goto free_all;
    }

    ret = EVP_PKEY_encrypt_init(ctx);
    if (ret != 1) {
        std::cout << "Error during encrypt init" << std::endl;
        goto free_all;
    }
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);

    EVP_PKEY_encrypt(ctx, NULL, &encryptedLen, msg, msg_len);
    std::cout << "encryptedLen:" << encryptedLen << std::endl;
    ret = EVP_PKEY_encrypt(ctx, encrypted_msg, &encryptedLen,
        msg, msg_len);
    if (ret != 1) {
        std::cout << "Error during encryption" << std::endl;
        goto free_all;
    }
    *encrypted_msg_len = encryptedLen;
    std::cout << "encrypted_msg_len:" << *encrypted_msg_len << std::endl;

free_all:

    EVP_PKEY_CTX_free(ctx);

}

void encryptWithPublicKey(const std::string& publicKey, const unsigned char* msg, size_t msg_len,
                                 unsigned char* encrypted_msg, size_t* encrypted_msg_len)
{
    int ret = 0;
    size_t encryptedLen = 0;
    BIO* bio = BIO_new_mem_buf(publicKey.c_str(), -1);
    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_encrypt_init(ctx);
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);

    EVP_PKEY_encrypt(ctx, NULL, &encryptedLen, msg, msg_len);
    std::cout << "encryptedLen:" << encryptedLen << std::endl;
    if (EVP_PKEY_encrypt(ctx, encrypted_msg, encrypted_msg_len, msg, msg_len) <= 0)
    {
        std::cout << "Failed to encrypt" << std::endl;
    }
    //*encrypted_msg_len = encryptedLen;
    std::cout << "encrypted_msg_len:" << *encrypted_msg_len << std::endl;
    if (bio) BIO_free_all(bio);
    if (pkey) EVP_PKEY_free(pkey);
    if (ctx) EVP_PKEY_CTX_free(ctx);
}


void RsaDecrypt(EVP_PKEY* pkey, const unsigned char* msg, size_t msg_len,
    unsigned char* decrypted_msg, size_t* decrypted_msg_len) {
    int ret = 0;
    EVP_PKEY_CTX* ctx = NULL;
    size_t decryptedLen = 0;

    // decrypt msg with rsa private key
    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        std::cout << "Error during context creation" << std::endl;
        goto free_all;
    }

    ret = EVP_PKEY_decrypt_init(ctx);
    if (ret != 1) {
        std::cout << "Error during decrypt init" << std::endl;
        goto free_all;
    }
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
    
    EVP_PKEY_decrypt(ctx, NULL, &decryptedLen, msg, msg_len);
    std::cout << "decryptedLen1:" << decryptedLen << std::endl;
    ret = EVP_PKEY_decrypt(ctx, decrypted_msg, &decryptedLen,
        msg, msg_len);
    if (ret != 1) {
        std::cout << "Error during decryption" << std::endl;
        goto free_all;
    }
    std::cout << "decryptedLen2:" << decryptedLen << std::endl;
    *decrypted_msg_len = decryptedLen;
    std::cout << "decrypted_msg_len:" << *decrypted_msg_len << std::endl;

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
        std::cout << "Error during context creation" << std::endl;
        goto free_all;
    }

    // initialize the encryption operation
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, iv)) {
        std::cout << "Error during encrypt init" << std::endl;
        goto free_all;
    }

    // provide the message to be encrypted, and obtain the encrypted output
    if (1 != EVP_EncryptUpdate(ctx, encrypted_msg, &len, msg, msg_len)) {
        std::cout << "Error during encryption" << std::endl;
        goto free_all;
    }

    *encrypted_msg_len = len;

    // finalize the encryption
    if (1 != EVP_EncryptFinal_ex(ctx, encrypted_msg + len, &len)) {
        std::cout << "Error during finalization of encryption" << std::endl;
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
        std::cout << "Error during context creation" << std::endl;
        goto free_all;
    }

    // initialize the decryption operation
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, iv)) {
        std::cout << "Error during decrypt init" << std::endl;
        goto free_all;
    }

    // provide the message to be decrypted, and obtain the decrypted output
    if (1 != EVP_DecryptUpdate(ctx, decrypted_msg, &len, msg, msg_len)) {
        std::cout << "Error during decryption" << std::endl;
        goto free_all;
    }

    *decrypted_msg_len = len;

    // finalize the decryption
    if (1 != EVP_DecryptFinal_ex(ctx, decrypted_msg + len, &len)) {
        std::cout << "Error during finalization of decryption" << std::endl;
        goto free_all;
    }

    *decrypted_msg_len += len;

free_all:

    EVP_CIPHER_CTX_free(ctx);

}

bool AesEncryptForSend(const unsigned char* msg, size_t msg_len,
    std::vector<unsigned char>* encrypted_msg, size_t* encrypted_msg_len) {
    unsigned char iv[IV_SIZE] = { 0 };
    unsigned char encrypted_data[BUFFER_SIZE] = { 0 };
    std::vector<unsigned char> result;
    if (!RAND_bytes(iv, sizeof(iv))) {
        std::cout << "Error during IV generation" << std::endl;
    }
    encrypted_msg->insert(encrypted_msg->end(), iv, iv + sizeof(iv));
    AesEncrypt(g_aes_key, sizeof(g_aes_key), iv, sizeof(iv), msg, msg_len, encrypted_data, encrypted_msg_len);
    encrypted_msg->insert(encrypted_msg->end(), encrypted_data, encrypted_data + *encrypted_msg_len);
    *encrypted_msg_len += IV_SIZE;
    return true;
}

bool AesDecryptForRecieve(const unsigned char* msg, size_t msg_len,
    std::vector<unsigned char>* decrypted_msg, size_t* decrypted_msg_len) {
    unsigned char decrypted_data[BUFFER_SIZE] = { 0 };
    std::vector<unsigned char> iv(msg, msg + IV_SIZE);
    AesDecrypt(g_aes_key, sizeof(g_aes_key), iv.data(), iv.size(),
        msg + IV_SIZE, msg_len - IV_SIZE, decrypted_data, decrypted_msg_len);
    decrypted_msg->insert(decrypted_msg->end(), decrypted_data, decrypted_data + *decrypted_msg_len);
    return true;
}

void CryptoInitialize() {
    std::cout << "================ Crypto Initialize ==============" << std::endl;
    std::string g_rsa_pub_key;
    EVP_PKEY* g_rsa_key = GenerateRsaKey(g_rsa_pub_key);

    GenerateAesKey(g_aes_key, sizeof(g_aes_key));

    const unsigned char* msg = (const unsigned char*)"Hello World!!!!!!!!!";
    size_t msg_len = strlen((const char*)msg);
    std::vector<unsigned char> encrypted_msg;
    std::vector<unsigned char> decrypted_msg;
    size_t encrypted_msg_len = 0;
    size_t decrypted_msg_len = 0;
    std::cout << "================ Encrypt Local Test ==============" << std::endl;
    AesEncryptForSend(msg, msg_len, &encrypted_msg, &encrypted_msg_len);
    std::cout << "encrypted_msg_len:"<< encrypted_msg_len <<"," << encrypted_msg.size() << std::endl;
    AesDecryptForRecieve(encrypted_msg.data(), encrypted_msg.size(), &decrypted_msg, &decrypted_msg_len);
    std::cout << "decrypted_msg_len:" << decrypted_msg_len << std::endl;
    std::cout << "decrypted_msg:" << decrypted_msg.data() << std::endl;
}

void CryptoTest() {
    std::string rsa_pub_key;
    EVP_PKEY* rsa_key = GenerateRsaKey(rsa_pub_key);

    unsigned char aes_key[32];
    GenerateAesKey(aes_key, sizeof(aes_key));

    unsigned char encrypted_aes_key[256];
    size_t encrypted_aes_key_len;

    const unsigned char* msg = (const unsigned char*)"Hello World!!!!!!!!!";
    size_t msg_len = strlen((const char*)msg);

    unsigned char iv[16] = { 0 };
    if (!RAND_bytes(iv, sizeof(iv))) {
        std::cout << "Error during IV generation" << std::endl;
    }
    unsigned char encrypted_msg[1024];
    size_t encrypted_msg_len;
    std::cout << "================ Encrypt data using AES key ==============" << std::endl;
    AesEncrypt(aes_key, sizeof(aes_key), iv, sizeof(iv),
        msg, msg_len,
        encrypted_msg, &encrypted_msg_len);
    std::cout << "================ Encrypt AES key using RSA Public key ==============" << std::endl;
    encryptWithPublicKey(rsa_pub_key, aes_key, sizeof(aes_key),
        encrypted_aes_key, &encrypted_aes_key_len);

    std::cout << "================ Decrypt AES key using RSA key ==============" << std::endl;
    unsigned char decrypted_aes_key[256];
    size_t decrypted_aes_key_len;
    RsaDecrypt(rsa_key, encrypted_aes_key, encrypted_aes_key_len,
        decrypted_aes_key, &decrypted_aes_key_len);

    std::cout << "================ Decrypt data using AES key ==============" << std::endl;
    unsigned char decrypted_msg[1024] = { 0 };
    size_t decrypted_msg_len;
    AesDecrypt(decrypted_aes_key, decrypted_aes_key_len, iv, sizeof(iv),
        encrypted_msg, encrypted_msg_len,
        decrypted_msg, &decrypted_msg_len);

    std::cout << "Original message: " << msg << std::endl;
    std::cout << "Decrypted message: " << decrypted_msg << std::endl;

    EVP_PKEY_free(rsa_key);
}

bool SetRecievedRsaPublicKey(std::string publickey)
{
    if (!publickey.length()) return false;
    g_recieved_rsa_pub_key = publickey;
    return true;
}

bool GenerateEncryptedKeyData(unsigned char* encrypted_key_data, size_t* encrypted_key_data_size)
{
     /*
     * | 32byte aes key | 256byte public key | 256byte recieved public key |
     * Total 544byte
     */
    if (!encrypted_key_data) return false;
    if (!g_recieved_rsa_pub_key.length()) return false;

    std::vector<unsigned char> key_data(g_aes_key, g_aes_key + sizeof(g_aes_key));
    key_data.insert(key_data.end(), g_rsa_pub_key.data(), g_rsa_pub_key.data() + g_rsa_pub_key.length());
    key_data.insert(key_data.end(), g_recieved_rsa_pub_key.data(),
        g_recieved_rsa_pub_key.data() + g_recieved_rsa_pub_key.length());
    std::cout << "key_data length:" << key_data.size() << std::endl;
    encryptWithPublicKey(g_recieved_rsa_pub_key, (const unsigned char*)g_recieved_rsa_pub_key.data(),
        g_recieved_rsa_pub_key.length(), encrypted_key_data, encrypted_key_data_size);

    return true;
}
