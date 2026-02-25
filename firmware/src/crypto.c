/**
 * @file crypto.c
 * @brief Cryptographic implementation for eCTF HSM
 * @date 2026
 *
 * wolfcrypt-only AES-GCM.  All DL_AESADV_* hardware calls removed.
 * Every GCM call uses wc_AesGcmSetKey / wc_AesGcmEncrypt / wc_AesGcmDecrypt.
 * The Aes context is stack-allocated, freed with wc_AesFree(), and zeroed
 * with secure_zero() on every path.  No global AES state persists.
 *
 * Include order:  wolfssl headers come first so that wolfssl/wolfcrypt/settings.h
 * sees our CFLAGS defines (HAVE_AES_GCM, WC_AES_BITSLICED, WC_NO_RNG, …)
 * before any conditional compilation in aes.h resolves.  Placing our own
 * headers first caused the GCM function prototypes to be conditionally
 * excluded because settings.h had not yet been processed.
 *
 * SCA countermeasures — two layers:
 *
 *   Layer 1  WC_AES_BITSLICED (build flag in Makefile)
 *     Wolfcrypt's table-free bitsliced AES.  All SubBytes operations are
 *     computed with pure bitwise logic — no S-box table lookups exist.
 *     Eliminates data-dependent memory access patterns (root cause of
 *     cache-DPA / SPA on table-based AES).  Requires HAVE_AES_ECB.
 *
 *   Layer 2  random_delay_wide() (before wc_AesGcmSetKey)
 *     Two TRNG bytes produce a 0–~20 ms jitter window.  CPA requires
 *     traces aligned to within a few samples; ±640 k sample positions of
 *     uncertainty forces an attacker to collect proportionally more traces
 *     or find a stable resynchronisation feature — which does not exist in
 *     bitsliced AES's flat power profile.
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

/*
 * wolfssl headers first — settings.h must resolve CFLAGS defines
 * (HAVE_AES_GCM, WC_AES_BITSLICED, WC_NO_RNG, …) before aes.h and hmac.h
 * apply their conditional guards.
 */
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/hmac.h>

#include "crypto.h"
#include "security.h"
#include "secrets.h"
#include <string.h>


/* -----------------------------------------------------------------------
 * crypto_init — no-op, retained for API compatibility.
 * ---------------------------------------------------------------------- */
int crypto_init(void)
{
    return 0;
}


/* -----------------------------------------------------------------------
 * generate_nonce — fill nonce_out with NONCE_SIZE TRNG bytes.
 * Loop counter i terminates at NONCE_SIZE exactly.
 * ---------------------------------------------------------------------- */
int generate_nonce(uint8_t *nonce_out)
{
    uint8_t i;

    if (nonce_out == NULL) { return -1; }

    for (i = 0; i < NONCE_SIZE; i++) {
        nonce_out[i] = trng_read_byte();
    }
    return 0;
}


/* -----------------------------------------------------------------------
 * aes_gcm_encrypt — AES-256-GCM encryption via wolfcrypt.
 *
 * SCA Layer 2: random_delay_wide() before wc_AesGcmSetKey slides the
 * key-schedule power signature across a ~20 ms trace window.
 * SCA Layer 1: WC_AES_BITSLICED build flag eliminates table-lookup leakage.
 * ---------------------------------------------------------------------- */
int aes_gcm_encrypt(const uint8_t *key,
                    const uint8_t *nonce,
                    const uint8_t *aad,        size_t aad_len,
                    const uint8_t *plaintext,  size_t pt_len,
                    uint8_t       *ciphertext,
                    uint8_t       *tag)
{
    Aes ctx;
    int ret;

    if (key == NULL || nonce == NULL || ciphertext == NULL || tag == NULL) {
        return -1;
    }
    if (aad_len > MAX_AAD_SIZE || pt_len > MAX_PLAINTEXT_SIZE) {
        return -1;
    }

    random_delay_wide();   /* SCA Layer 2 */

    ret = wc_AesGcmSetKey(&ctx, key, GCM_KEY_SIZE);
    if (ret != 0) {
        wc_AesFree(&ctx);
        secure_zero(&ctx, sizeof(Aes));
        return -1;
    }

    ret = wc_AesGcmEncrypt(&ctx,
                           ciphertext, plaintext, (word32)pt_len,
                           nonce,      NONCE_SIZE,
                           tag,        TAG_SIZE,
                           aad,        (word32)aad_len);

    wc_AesFree(&ctx);
    secure_zero(&ctx, sizeof(Aes));

    return (ret == 0) ? 0 : -1;
}


/* -----------------------------------------------------------------------
 * aes_gcm_decrypt — AES-256-GCM decryption via wolfcrypt.
 *
 * wc_AesGcmDecrypt returns AES_GCM_AUTH_E on tag failure but still writes
 * to the output buffer.  On non-zero return the plaintext buffer is zeroed
 * before returning -1 — no partial plaintext leaks to the caller.
 * ---------------------------------------------------------------------- */
int aes_gcm_decrypt(const uint8_t *key,
                    const uint8_t *nonce,
                    const uint8_t *aad,        size_t aad_len,
                    const uint8_t *ciphertext, size_t ct_len,
                    const uint8_t *tag,
                    uint8_t       *plaintext)
{
    Aes ctx;
    int ret;

    if (key == NULL || nonce == NULL || tag == NULL || plaintext == NULL) {
        return -1;
    }
    if (aad_len > MAX_AAD_SIZE || ct_len > MAX_PLAINTEXT_SIZE) {
        return -1;
    }

    random_delay_wide();   /* SCA Layer 2 */

    ret = wc_AesGcmSetKey(&ctx, key, GCM_KEY_SIZE);
    if (ret != 0) {
        wc_AesFree(&ctx);
        secure_zero(&ctx, sizeof(Aes));
        return -1;
    }

    ret = wc_AesGcmDecrypt(&ctx,
                           plaintext, ciphertext, (word32)ct_len,
                           nonce,     NONCE_SIZE,
                           tag,       TAG_SIZE,
                           aad,       (word32)aad_len);

    wc_AesFree(&ctx);
    secure_zero(&ctx, sizeof(Aes));

    if (ret != 0) {
        secure_zero(plaintext, ct_len);   /* don't leak partial plaintext */
        return -1;
    }
    return 0;
}


/* -----------------------------------------------------------------------
 * hmac_sha256 — HMAC-SHA256 with mandatory domain separator.
 *
 * Computes HMAC(key, data || domain) using two wc_HmacUpdate calls so no
 * temporary concatenation buffer is needed on the stack.
 * ---------------------------------------------------------------------- */
int hmac_sha256(const uint8_t *key,
                const uint8_t *data, size_t data_len,
                const char    *domain,
                uint8_t       *output)
{
    Hmac ctx;
    int  ret;

    if (key == NULL || output == NULL || domain == NULL) { return -1; }
    if (data == NULL && data_len > 0)                   { return -1; }

    ret = wc_HmacInit(&ctx, NULL, INVALID_DEVID);
    if (ret != 0) { return -1; }

    ret = wc_HmacSetKey(&ctx, WC_SHA256, key, HMAC_SIZE);
    if (ret != 0) { goto hmac_fail; }

    if (data != NULL && data_len > 0) {
        ret = wc_HmacUpdate(&ctx, data, (word32)data_len);
        if (ret != 0) { goto hmac_fail; }
    }

    /* Domain separator appended as a second Update — no temp buffer. */
    ret = wc_HmacUpdate(&ctx,
                        (const uint8_t *)domain,
                        (word32)strlen(domain));
    if (ret != 0) { goto hmac_fail; }

    ret = wc_HmacFinal(&ctx, output);

hmac_fail:
    wc_HmacFree(&ctx);
    secure_zero(&ctx, sizeof(Hmac));
    return (ret == 0) ? 0 : -1;
}


/* -----------------------------------------------------------------------
 * hmac_verify — constant-time, glitch-resistant HMAC comparison.
 *
 * Computes the MAC twice with random_delay() between passes.
 * security_halt() if the two results differ (fault injection attempt).
 * Final comparison uses secure_compare() — no early exit.
 * ---------------------------------------------------------------------- */
bool hmac_verify(const uint8_t *key,
                 const uint8_t *data, size_t data_len,
                 const char    *domain,
                 const uint8_t *expected)
{
    uint8_t mac1[HMAC_SIZE];
    uint8_t mac2[HMAC_SIZE];
    bool    result;

    if (key == NULL || expected == NULL || domain == NULL) { return false; }

    if (hmac_sha256(key, data, data_len, domain, mac1) != 0) {
        secure_zero(mac1, sizeof(mac1));
        return false;
    }

    random_delay();

    if (hmac_sha256(key, data, data_len, domain, mac2) != 0) {
        secure_zero(mac1, sizeof(mac1));
        secure_zero(mac2, sizeof(mac2));
        return false;
    }

    /* Both passes must agree — disagreement signals fault injection. */
    if (!secure_compare(mac1, mac2, HMAC_SIZE)) {
        security_halt();
    }

    result = secure_compare(mac1, expected, HMAC_SIZE);

    secure_zero(mac1, sizeof(mac1));
    secure_zero(mac2, sizeof(mac2));
    return result;
}


/* -----------------------------------------------------------------------
 * build_storage_aad — slot(1) || uuid(16) || group_id(2 LE) || name(32)
 * Returns STORAGE_AAD_SIZE (51).
 * Name is zero-padded to 32 bytes; bounded loop avoids strlen on flash data.
 * ---------------------------------------------------------------------- */
size_t build_storage_aad(uint8_t slot, const uint8_t *uuid,
                         uint16_t group_id, const char *name,
                         uint8_t *out)
{
    uint8_t i;
    uint8_t pos = 0;

    out[pos++] = slot;

    /* uuid — loop counter i in [0, 16) */
    for (i = 0; i < 16; i++) { out[pos++] = uuid[i]; }

    /* group_id little-endian */
    out[pos++] = (uint8_t)(group_id & 0xFF);
    out[pos++] = (uint8_t)((group_id >> 8) & 0xFF);

    /* name zero-padded — loop counter i in [0, 32) */
    for (i = 0; i < 32; i++) {
        out[pos++] = (name != NULL && name[i] != '\0') ? (uint8_t)name[i] : 0;
    }

    return STORAGE_AAD_SIZE;   /* 51 */
}


/* -----------------------------------------------------------------------
 * build_transfer_aad — recv_chal(12) || send_chal(12) || slot(1)
 *                      || uuid(16) || group_id(2 LE) || name(32)
 * Returns TRANSFER_AAD_SIZE (75).
 * ---------------------------------------------------------------------- */
size_t build_transfer_aad(const uint8_t *recv_chal,
                          const uint8_t *send_chal,
                          uint8_t        slot,
                          const uint8_t *uuid,
                          uint16_t       group_id,
                          const char    *name,
                          uint8_t       *out)
{
    uint8_t i;
    uint8_t pos = 0;

    /* recv_chal — loop counter i in [0, 12) */
    for (i = 0; i < 12; i++) { out[pos++] = recv_chal[i]; }

    /* send_chal — loop counter i in [0, 12) */
    for (i = 0; i < 12; i++) { out[pos++] = send_chal[i]; }

    out[pos++] = slot;

    /* uuid — loop counter i in [0, 16) */
    for (i = 0; i < 16; i++) { out[pos++] = uuid[i]; }

    /* group_id little-endian */
    out[pos++] = (uint8_t)(group_id & 0xFF);
    out[pos++] = (uint8_t)((group_id >> 8) & 0xFF);

    /* name zero-padded — loop counter i in [0, 32) */
    for (i = 0; i < 32; i++) {
        out[pos++] = (name != NULL && name[i] != '\0') ? (uint8_t)name[i] : 0;
    }

    return TRANSFER_AAD_SIZE;  /* 75 */
}
