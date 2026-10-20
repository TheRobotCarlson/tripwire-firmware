/* tw_aead_openssl.c — AES-128-GCM for tw_codec host tests. */
#include "tw_codec.h"

#include <openssl/evp.h>

int tw_gcm_seal(const uint8_t key[TW_KEY_LEN], const uint8_t iv[TW_IV_LEN],
                const uint8_t *pt, size_t len, uint8_t *ct, uint8_t tag[TW_TAG_LEN])
{
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    int n = 0, ok = c &&
        EVP_EncryptInit_ex(c, EVP_aes_128_gcm(), NULL, NULL, NULL) &&
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, TW_IV_LEN, NULL) &&
        EVP_EncryptInit_ex(c, NULL, NULL, key, iv) &&
        EVP_EncryptUpdate(c, ct, &n, pt, (int)len) &&
        EVP_EncryptFinal_ex(c, ct + n, &n) &&
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, TW_TAG_LEN, tag);
    EVP_CIPHER_CTX_free(c);
    return ok ? 0 : -1;
}

int tw_gcm_open(const uint8_t key[TW_KEY_LEN], const uint8_t iv[TW_IV_LEN],
                const uint8_t *ct, size_t len, const uint8_t tag[TW_TAG_LEN], uint8_t *pt)
{
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    int n = 0, ok = c &&
        EVP_DecryptInit_ex(c, EVP_aes_128_gcm(), NULL, NULL, NULL) &&
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, TW_IV_LEN, NULL) &&
        EVP_DecryptInit_ex(c, NULL, NULL, key, iv) &&
        EVP_DecryptUpdate(c, pt, &n, ct, (int)len) &&
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, TW_TAG_LEN, (void *)tag) &&
        EVP_DecryptFinal_ex(c, pt + n, &n) > 0;
    EVP_CIPHER_CTX_free(c);
    return ok ? 0 : -1;
}
