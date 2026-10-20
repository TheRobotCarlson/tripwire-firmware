/*
 * tw_aead_psa.c — AES-128-GCM for tw_codec on ESP-IDF (PSA Crypto, mbedtls 4.x).
 */
#include "tw_codec.h"

#include "psa/crypto.h"

static int import_key(const uint8_t key[TW_KEY_LEN], psa_key_usage_t usage, psa_key_id_t *kid)
{
    if (psa_crypto_init() != PSA_SUCCESS) return -1;
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attr, usage);
    psa_set_key_algorithm(&attr, PSA_ALG_GCM);
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attr, 128);
    return psa_import_key(&attr, key, TW_KEY_LEN, kid) == PSA_SUCCESS ? 0 : -1;
}

int tw_gcm_seal(const uint8_t key[TW_KEY_LEN], const uint8_t iv[TW_IV_LEN],
                const uint8_t *pt, size_t len, uint8_t *ct, uint8_t tag[TW_TAG_LEN])
{
    psa_key_id_t kid;
    if (import_key(key, PSA_KEY_USAGE_ENCRYPT, &kid) != 0) return -1;

    /* PSA writes ciphertext || tag contiguously; tw_codec always passes
     * tag == ct + len, which the packet layout guarantees. */
    size_t out_len = 0;
    psa_status_t st = psa_aead_encrypt(kid, PSA_ALG_GCM, iv, TW_IV_LEN, NULL, 0,
                                       pt, len, ct, len + TW_TAG_LEN, &out_len);
    psa_destroy_key(kid);
    if (st != PSA_SUCCESS || out_len != len + TW_TAG_LEN || tag != ct + len) return -1;
    return 0;
}

int tw_gcm_open(const uint8_t key[TW_KEY_LEN], const uint8_t iv[TW_IV_LEN],
                const uint8_t *ct, size_t len, const uint8_t tag[TW_TAG_LEN], uint8_t *pt)
{
    if (tag != ct + len) return -1;
    psa_key_id_t kid;
    if (import_key(key, PSA_KEY_USAGE_DECRYPT, &kid) != 0) return -1;
    size_t out_len = 0;
    psa_status_t st = psa_aead_decrypt(kid, PSA_ALG_GCM, iv, TW_IV_LEN, NULL, 0,
                                       ct, len + TW_TAG_LEN, pt, len, &out_len);
    psa_destroy_key(kid);
    return (st == PSA_SUCCESS && out_len == len) ? 0 : -1;
}
