/**
 * @file crypto.c
 * @brief Cryptographic implementation for eCTF HSM
 * @date 2026
 *
 * Key split: aes_gcm_encrypt() and aes_gcm_decrypt() accept an explicit key
 *   parameter.  Call sites pass STORAGE_KEY (at rest) or TRANSFER_KEY (in
 *   transit).
 *
 * Fix #5 (alignment): DL_AESADV_loadInputDataAligned /
 *   readOutputDataAligned require 4-byte-aligned pointers.  All data flows
 *   through local aligned block_in / block_out buffers.
 *
 * Fix #6 (infinite AES polling): every hardware busy-wait has an explicit
 *   iteration counter; security_halt() on expiry.
 *
 * Fix #11 (strlen on untrusted name): bounded manual scan in both
 *   build_storage_aad() and build_transfer_aad().
 *
 * FIX C (P5): build_transfer_aad() includes a 32-byte zero-padded name
 *   field.  Transfer AAD = 75 bytes.
 *
 * SCA (side-channel) mitigations — two layers applied to every key load:
 *
 *   1. Wide jitter (random_delay_wide): two TRNG bytes → 0–~20 ms window
 *      before load_key_to_aes().  CPA must average through the noise;
 *      wider window proportionally increases required trace count.
 *
 *   2. Dummy AES-ECB operation (dummy_aes_ecb): one AES-ECB block with a
 *      fresh TRNG key and TRNG plaintext, discarded immediately.  A TRNG
 *      bit randomly places the dummy BEFORE or AFTER the real GCM operation,
 *      so the real key-load event appears at two different trace positions.
 *      The attacker cannot reliably align to the trigger without knowing
 *      which position contained the real key.
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#include "crypto.h"
#include "security.h"
#include "secrets.h"
#include "filesystem.h"
#include "ti_msp_dl_config.h"
#include <ti/driverlib/dl_aesadv.h>
#include <ti/devices/msp/msp.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <string.h>

/* All local buffers passed to the Aligned AES API must be 4-byte aligned. */
#define ALIGNED_BUFFER __attribute__((aligned(4)))

/* Maximum AES peripheral poll iterations before security_halt(). ~100 K.
 * At 32 MHz with ~5 cycles/iteration ≈ 15 ms — far above hardware spec. */
#define AES_POLL_LIMIT 100000UL

/* ------------------------------------------------------------------ */
/* Internal: load a 32-byte key into AESADV registers.                */
/* Key must be 4-byte aligned (STORAGE_KEY and TRANSFER_KEY satisfy   */
/* this via __attribute__((aligned(4))) in secrets.c).                */
/* ------------------------------------------------------------------ */
static void load_key_to_aes(const uint8_t *key)
{
    DL_AESADV_setKeyAligned(AESADV, (const uint32_t *)key,
                            DL_AESADV_KEY_SIZE_256_BIT);
}

/* ------------------------------------------------------------------ */
/* dummy_aes_ecb — SCA dummy operation.                               */
/*                                                                     */
/* Runs one AES-256-ECB block with a TRNG-generated key and TRNG      */
/* plaintext.  The ciphertext output is read into a volatile discard  */
/* buffer so the compiler cannot elide the operation, then zeroed.     */
/*                                                                     */
/* Purpose: populate the trace window with an indistinguishable key-  */
/* load event so the attacker cannot determine which AES operation in  */
/* the window used the real secret key.  The dummy key is fresh each  */
/* call; CPA against it recovers only ephemeral randomness.            */
/* ------------------------------------------------------------------ */
static void dummy_aes_ecb(void)
{
    ALIGNED_BUFFER uint8_t dummy_key[32];
    ALIGNED_BUFFER uint8_t dummy_block[AES_BLOCK_SIZE];
    ALIGNED_BUFFER volatile uint8_t dummy_out[AES_BLOCK_SIZE];
    uint32_t poll_i;
    uint8_t  i;

    /* Fill dummy key and block from TRNG — independent of any secret.
     * Loop counter i in [0, 32). */
    for (i = 0; i < 32; i++) {
        dummy_key[i] = trng_read_byte();
    }
    /* Loop counter i in [0, AES_BLOCK_SIZE). */
    for (i = 0; i < AES_BLOCK_SIZE; i++) {
        dummy_block[i] = trng_read_byte();
    }

    DL_AESADV_Config ecbConfig = {
        .mode              = DL_AESADV_MODE_ECB,
        .direction         = DL_AESADV_DIR_ENCRYPT,
        .ctr_ctrWidth      = DL_AESADV_CTR_WIDTH_32_BIT,
        .cfb_fbWidth       = DL_AESADV_FB_WIDTH_128,
        .ccm_ctrWidth      = DL_AESADV_CCM_CTR_WIDTH_2_BYTES,
        .ccm_tagWidth      = DL_AESADV_CCM_TAG_WIDTH_1_BYTE,
        .iv                = NULL,
        .nonce             = NULL,
        .lowerCryptoLength = AES_BLOCK_SIZE,
        .upperCryptoLength = 0,
        .aadLength         = 0,
    };

    /* Key load — power profile matches real load_key_to_aes(). */
    DL_AESADV_setKeyAligned(AESADV, (const uint32_t *)dummy_key,
                            DL_AESADV_KEY_SIZE_256_BIT);
    DL_AESADV_initECB(AESADV, &ecbConfig);

    /* Encrypt one block; poll with limit. */
    for (poll_i = 0;
         !DL_AESADV_isInputReady(AESADV) && poll_i < AES_POLL_LIMIT;
         poll_i++) {}
    if (poll_i >= AES_POLL_LIMIT) { security_halt(); }

    DL_AESADV_loadInputDataAligned(AESADV, (const uint32_t *)dummy_block);

    for (poll_i = 0;
         !DL_AESADV_isOutputReady(AESADV) && poll_i < AES_POLL_LIMIT;
         poll_i++) {}
    if (poll_i >= AES_POLL_LIMIT) { security_halt(); }

    /* Read output into volatile buffer — prevents compiler elision. */
    DL_AESADV_readOutputDataAligned(AESADV, (uint32_t *)dummy_out);

    /* Zero all locals. */
    secure_zero(dummy_key,   sizeof(dummy_key));
    secure_zero(dummy_block, sizeof(dummy_block));
    /* volatile discard buffer — write directly so it is not optimised away. */
    for (i = 0; i < AES_BLOCK_SIZE; i++) {
        dummy_out[i] = 0;
    }
}

int crypto_init(void)
{
    /* No persistent state; key is loaded per operation. */
    return 0;
}

/* ------------------------------------------------------------------ */
/* AES-256-GCM Encrypt                                                 */
/*                                                                     */
/* plaintext → ciphertext; writes 16-byte GCM tag.                   */
/* Pass STORAGE_KEY for at-rest, TRANSFER_KEY for in-transit.         */
/* Returns 0 on success, -1 on error.                                  */
/*                                                                     */
/* SCA flow:                                                           */
/*   1. random_delay_wide()  — 0–~20 ms pre-sequence jitter.          */
/*   2. TRNG bit selects dummy position: 0 = dummy first, 1 = real    */
/*      first.  Real key-load appears at two possible trace positions. */
/* ------------------------------------------------------------------ */
int aes_gcm_encrypt(const uint8_t *key,
                    const uint8_t *nonce,
                    const uint8_t *aad,       size_t aad_len,
                    const uint8_t *plaintext,  size_t pt_len,
                    uint8_t *ciphertext,
                    uint8_t *tag)
{
    ALIGNED_BUFFER uint8_t iv_buf[16];
    ALIGNED_BUFFER uint8_t block_in[AES_BLOCK_SIZE];
    ALIGNED_BUFFER uint8_t block_out[AES_BLOCK_SIZE];

    size_t   full_blocks, remaining, i;
    uint32_t poll_i;
    uint8_t  order_bit;

    if (key == NULL || nonce == NULL || tag == NULL) { return -1; }
    if ((aad == NULL && aad_len > 0) || aad_len > MAX_AAD_SIZE) { return -1; }
    if ((plaintext == NULL && pt_len > 0) || pt_len > MAX_PLAINTEXT_SIZE) { return -1; }
    if (ciphertext == NULL && pt_len > 0) { return -1; }

    /* --- SCA: wide jitter before the key-load window. --- */
    random_delay_wide();

    /* --- SCA: TRNG bit decides dummy placement. --- */
    order_bit = trng_read_byte() & 0x01;
    if (order_bit == 0) {
        dummy_aes_ecb();  /* dummy first; real key load comes after */
    }

    /* IV: 12-byte nonce || 0x00000001 */
    memset(iv_buf, 0, sizeof(iv_buf));
    memcpy(iv_buf, nonce, NONCE_SIZE);
    iv_buf[15] = 0x01;

    DL_AESADV_Config gcmConfig = {
        .mode              = DL_AESADV_MODE_GCM_AUTONOMOUS,
        .direction         = DL_AESADV_DIR_ENCRYPT,
        .ctr_ctrWidth      = DL_AESADV_CTR_WIDTH_32_BIT,
        .cfb_fbWidth       = DL_AESADV_FB_WIDTH_128,
        .ccm_ctrWidth      = DL_AESADV_CCM_CTR_WIDTH_2_BYTES,
        .ccm_tagWidth      = DL_AESADV_CCM_TAG_WIDTH_1_BYTE,
        .iv                = iv_buf,
        .nonce             = NULL,
        .lowerCryptoLength = (uint32_t)pt_len,
        .upperCryptoLength = 0,
        .aadLength         = (uint32_t)aad_len,
    };

    load_key_to_aes(key);
    DL_AESADV_initGCM(AESADV, &gcmConfig);

    /* --- Process AAD blocks (authenticated only, not encrypted) --- */
    size_t aad_full   = aad_len / AES_BLOCK_SIZE;
    size_t aad_remain = aad_len % AES_BLOCK_SIZE;

    /* Loop counter i in [0, aad_full). */
    for (i = 0; i < aad_full; i++) {
        memcpy(block_in, aad + i * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
        for (poll_i = 0;
             !DL_AESADV_isInputReady(AESADV) && poll_i < AES_POLL_LIMIT;
             poll_i++) {}
        if (poll_i >= AES_POLL_LIMIT) { security_halt(); }
        DL_AESADV_loadInputDataAligned(AESADV, (const uint32_t *)block_in);
    }
    if (aad_remain > 0) {
        memset(block_in, 0, AES_BLOCK_SIZE);
        memcpy(block_in, aad + aad_full * AES_BLOCK_SIZE, aad_remain);
        for (poll_i = 0;
             !DL_AESADV_isInputReady(AESADV) && poll_i < AES_POLL_LIMIT;
             poll_i++) {}
        if (poll_i >= AES_POLL_LIMIT) { security_halt(); }
        DL_AESADV_loadInputDataAligned(AESADV, (const uint32_t *)block_in);
    }

    /* --- Process plaintext blocks --- */
    full_blocks = pt_len / AES_BLOCK_SIZE;
    remaining   = pt_len % AES_BLOCK_SIZE;

    /* Loop counter i in [0, full_blocks). */
    for (i = 0; i < full_blocks; i++) {
        memcpy(block_in, plaintext + i * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
        for (poll_i = 0;
             !DL_AESADV_isInputReady(AESADV) && poll_i < AES_POLL_LIMIT;
             poll_i++) {}
        if (poll_i >= AES_POLL_LIMIT) { security_halt(); }
        DL_AESADV_loadInputDataAligned(AESADV, (const uint32_t *)block_in);

        for (poll_i = 0;
             !DL_AESADV_isOutputReady(AESADV) && poll_i < AES_POLL_LIMIT;
             poll_i++) {}
        if (poll_i >= AES_POLL_LIMIT) { security_halt(); }
        DL_AESADV_readOutputDataAligned(AESADV, (uint32_t *)block_out);
        memcpy(ciphertext + i * AES_BLOCK_SIZE, block_out, AES_BLOCK_SIZE);
    }

    if (remaining > 0) {
        memset(block_in, 0, AES_BLOCK_SIZE);
        memcpy(block_in, plaintext + full_blocks * AES_BLOCK_SIZE, remaining);
        for (poll_i = 0;
             !DL_AESADV_isInputReady(AESADV) && poll_i < AES_POLL_LIMIT;
             poll_i++) {}
        if (poll_i >= AES_POLL_LIMIT) { security_halt(); }
        DL_AESADV_loadInputDataAligned(AESADV, (const uint32_t *)block_in);

        for (poll_i = 0;
             !DL_AESADV_isOutputReady(AESADV) && poll_i < AES_POLL_LIMIT;
             poll_i++) {}
        if (poll_i >= AES_POLL_LIMIT) { security_halt(); }
        DL_AESADV_readOutputDataAligned(AESADV, (uint32_t *)block_out);
        memcpy(ciphertext + full_blocks * AES_BLOCK_SIZE, block_out, remaining);
    }

    /* --- Read GCM authentication tag --- */
    ALIGNED_BUFFER uint8_t tag_buf[TAG_SIZE];
    for (poll_i = 0;
         !DL_AESADV_isOutputReady(AESADV) && poll_i < AES_POLL_LIMIT;
         poll_i++) {}
    if (poll_i >= AES_POLL_LIMIT) { security_halt(); }
    DL_AESADV_readTAGAligned(AESADV, (uint32_t *)tag_buf);
    memcpy(tag, tag_buf, TAG_SIZE);

    /* --- SCA: dummy after real if order_bit == 1 --- */
    if (order_bit == 1) {
        dummy_aes_ecb();
    }

    memset(iv_buf,    0, sizeof(iv_buf));
    memset(block_in,  0, sizeof(block_in));
    memset(block_out, 0, sizeof(block_out));
    memset(tag_buf,   0, sizeof(tag_buf));

    return 0;
}

/* ------------------------------------------------------------------ */
/* AES-256-GCM Decrypt                                                 */
/*                                                                     */
/* Zeros plaintext on tag mismatch or any error.                       */
/* Pass STORAGE_KEY for at-rest, TRANSFER_KEY for in-transit.         */
/* Returns 0 on success, -1 on failure.                                */
/*                                                                     */
/* SCA flow mirrors encrypt: wide jitter + randomised dummy placement. */
/* ------------------------------------------------------------------ */
int aes_gcm_decrypt(const uint8_t *key,
                    const uint8_t *nonce,
                    const uint8_t *aad,        size_t aad_len,
                    const uint8_t *ciphertext,  size_t ct_len,
                    const uint8_t *tag,
                    uint8_t *plaintext)
{
    ALIGNED_BUFFER uint8_t iv_buf[16];
    ALIGNED_BUFFER uint8_t block_in[AES_BLOCK_SIZE];
    ALIGNED_BUFFER uint8_t block_out[AES_BLOCK_SIZE];
    ALIGNED_BUFFER uint8_t computed_tag[TAG_SIZE];

    size_t   full_blocks, remaining, i;
    uint32_t poll_i;
    uint8_t  order_bit;

    if (key == NULL || nonce == NULL || tag == NULL) { return -1; }
    if ((aad == NULL && aad_len > 0) || aad_len > MAX_AAD_SIZE) { return -1; }
    if ((ciphertext == NULL && ct_len > 0) || ct_len > MAX_PLAINTEXT_SIZE) { return -1; }
    if (plaintext == NULL && ct_len > 0) { return -1; }

    /* --- SCA: wide jitter before the key-load window. --- */
    random_delay_wide();

    /* --- SCA: TRNG bit decides dummy placement. --- */
    order_bit = trng_read_byte() & 0x01;
    if (order_bit == 0) {
        dummy_aes_ecb();  /* dummy first; real key load comes after */
    }

    memset(iv_buf, 0, sizeof(iv_buf));
    memcpy(iv_buf, nonce, NONCE_SIZE);
    iv_buf[15] = 0x01;

    DL_AESADV_Config gcmConfig = {
        .mode              = DL_AESADV_MODE_GCM_AUTONOMOUS,
        .direction         = DL_AESADV_DIR_DECRYPT,
        .ctr_ctrWidth      = DL_AESADV_CTR_WIDTH_32_BIT,
        .cfb_fbWidth       = DL_AESADV_FB_WIDTH_128,
        .ccm_ctrWidth      = DL_AESADV_CCM_CTR_WIDTH_2_BYTES,
        .ccm_tagWidth      = DL_AESADV_CCM_TAG_WIDTH_1_BYTE,
        .iv                = iv_buf,
        .nonce             = NULL,
        .lowerCryptoLength = (uint32_t)ct_len,
        .upperCryptoLength = 0,
        .aadLength         = (uint32_t)aad_len,
    };

    load_key_to_aes(key);
    DL_AESADV_initGCM(AESADV, &gcmConfig);

    /* --- Process AAD blocks --- */
    size_t aad_full   = aad_len / AES_BLOCK_SIZE;
    size_t aad_remain = aad_len % AES_BLOCK_SIZE;

    /* Loop counter i in [0, aad_full). */
    for (i = 0; i < aad_full; i++) {
        memcpy(block_in, aad + i * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
        for (poll_i = 0;
             !DL_AESADV_isInputReady(AESADV) && poll_i < AES_POLL_LIMIT;
             poll_i++) {}
        if (poll_i >= AES_POLL_LIMIT) { security_halt(); }
        DL_AESADV_loadInputDataAligned(AESADV, (const uint32_t *)block_in);
    }
    if (aad_remain > 0) {
        memset(block_in, 0, AES_BLOCK_SIZE);
        memcpy(block_in, aad + aad_full * AES_BLOCK_SIZE, aad_remain);
        for (poll_i = 0;
             !DL_AESADV_isInputReady(AESADV) && poll_i < AES_POLL_LIMIT;
             poll_i++) {}
        if (poll_i >= AES_POLL_LIMIT) { security_halt(); }
        DL_AESADV_loadInputDataAligned(AESADV, (const uint32_t *)block_in);
    }

    /* --- Process ciphertext blocks --- */
    full_blocks = ct_len / AES_BLOCK_SIZE;
    remaining   = ct_len % AES_BLOCK_SIZE;

    /* Loop counter i in [0, full_blocks). */
    for (i = 0; i < full_blocks; i++) {
        memcpy(block_in, ciphertext + i * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
        for (poll_i = 0;
             !DL_AESADV_isInputReady(AESADV) && poll_i < AES_POLL_LIMIT;
             poll_i++) {}
        if (poll_i >= AES_POLL_LIMIT) { security_halt(); }
        DL_AESADV_loadInputDataAligned(AESADV, (const uint32_t *)block_in);

        for (poll_i = 0;
             !DL_AESADV_isOutputReady(AESADV) && poll_i < AES_POLL_LIMIT;
             poll_i++) {}
        if (poll_i >= AES_POLL_LIMIT) { security_halt(); }
        DL_AESADV_readOutputDataAligned(AESADV, (uint32_t *)block_out);
        memcpy(plaintext + i * AES_BLOCK_SIZE, block_out, AES_BLOCK_SIZE);
    }

    if (remaining > 0) {
        memset(block_in, 0, AES_BLOCK_SIZE);
        memcpy(block_in, ciphertext + full_blocks * AES_BLOCK_SIZE, remaining);
        for (poll_i = 0;
             !DL_AESADV_isInputReady(AESADV) && poll_i < AES_POLL_LIMIT;
             poll_i++) {}
        if (poll_i >= AES_POLL_LIMIT) { security_halt(); }
        DL_AESADV_loadInputDataAligned(AESADV, (const uint32_t *)block_in);

        for (poll_i = 0;
             !DL_AESADV_isOutputReady(AESADV) && poll_i < AES_POLL_LIMIT;
             poll_i++) {}
        if (poll_i >= AES_POLL_LIMIT) { security_halt(); }
        DL_AESADV_readOutputDataAligned(AESADV, (uint32_t *)block_out);
        memcpy(plaintext + full_blocks * AES_BLOCK_SIZE, block_out, remaining);
    }

    /* --- Read computed tag, then verify --- */
    for (poll_i = 0;
         !DL_AESADV_isOutputReady(AESADV) && poll_i < AES_POLL_LIMIT;
         poll_i++) {}
    if (poll_i >= AES_POLL_LIMIT) {
        secure_zero(plaintext, ct_len);
        security_halt();
    }
    DL_AESADV_readTAGAligned(AESADV, (uint32_t *)computed_tag);

    /* --- SCA: dummy after real if order_bit == 1 --- */
    if (order_bit == 1) {
        dummy_aes_ecb();
    }

    /* Constant-time tag comparison; zero plaintext on mismatch. */
    if (!secure_compare(computed_tag, tag, TAG_SIZE)) {
        secure_zero(plaintext,    ct_len);
        secure_zero(computed_tag, TAG_SIZE);
        memset(iv_buf,    0, sizeof(iv_buf));
        memset(block_in,  0, sizeof(block_in));
        memset(block_out, 0, sizeof(block_out));
        return -1;
    }

    memset(iv_buf,    0, sizeof(iv_buf));
    memset(block_in,  0, sizeof(block_in));
    memset(block_out, 0, sizeof(block_out));
    memset(computed_tag, 0, TAG_SIZE);

    return 0;
}

/*
 * HMAC-SHA256 with mandatory domain separator.
 * Computes HMAC(key, data || domain) — matches Python compute_hmac().
 */
int hmac_sha256(const uint8_t *key,
                const uint8_t *data, size_t data_len,
                const char *domain,
                uint8_t *output)
{
    Hmac   hmac;
    int    ret;
    size_t domain_len;
    size_t i;

    if (key == NULL || (data == NULL && data_len > 0) ||
        domain == NULL || output == NULL) {
        return -1;
    }

    /* Bounded domain length — loop counter i in [0, HMAC_DOMAIN_MAX_LEN). */
    domain_len = 0;
    for (i = 0; i < 64 && domain[i] != '\0'; i++) {
        domain_len++;
    }

    ret = wc_HmacInit(&hmac, NULL, INVALID_DEVID);
    if (ret != 0) { return -1; }

    ret = wc_HmacSetKey(&hmac, WC_SHA256, key, 32);
    if (ret != 0) { wc_HmacFree(&hmac); return -1; }

    if (data_len > 0) {
        ret = wc_HmacUpdate(&hmac, (const byte *)data, (word32)data_len);
        if (ret != 0) { wc_HmacFree(&hmac); return -1; }
    }

    ret = wc_HmacUpdate(&hmac, (const byte *)domain, (word32)domain_len);
    if (ret != 0) { wc_HmacFree(&hmac); return -1; }

    ret = wc_HmacFinal(&hmac, output);
    wc_HmacFree(&hmac);
    return (ret == 0) ? 0 : -1;
}

/*
 * Verify HMAC-SHA256 — constant-time, glitch-resistant.
 * Computes twice with random_delay between; security_halt() on mismatch.
 */
bool hmac_verify(const uint8_t *key,
                 const uint8_t *data, size_t data_len,
                 const char *domain,
                 const uint8_t *expected_mac)
{
    uint8_t mac1[HMAC_SIZE];
    uint8_t mac2[HMAC_SIZE];
    bool    result1, result2;

    if (key == NULL || (data == NULL && data_len > 0) ||
        domain == NULL || expected_mac == NULL) {
        return false;
    }

    if (hmac_sha256(key, data, data_len, domain, mac1) != 0) {
        memset(mac1, 0, HMAC_SIZE);
        return false;
    }
    result1 = secure_compare(mac1, expected_mac, HMAC_SIZE);

    random_delay();

    if (hmac_sha256(key, data, data_len, domain, mac2) != 0) {
        memset(mac1, 0, HMAC_SIZE);
        memset(mac2, 0, HMAC_SIZE);
        return false;
    }
    result2 = secure_compare(mac2, expected_mac, HMAC_SIZE);

    /* Both passes must agree; disagreement indicates fault injection. */
    if ((bool)result1 != (bool)result2) {
        memset(mac1, 0, HMAC_SIZE);
        memset(mac2, 0, HMAC_SIZE);
        security_halt();
    }

    memset(mac1, 0, HMAC_SIZE);
    memset(mac2, 0, HMAC_SIZE);
    return result1;
}

/*
 * Generate 12-byte nonce from hardware TRNG.
 */
int generate_nonce(uint8_t *nonce)
{
    uint8_t i;

    if (nonce == NULL) { return -1; }

    /* Loop counter i in [0, NONCE_SIZE). */
    for (i = 0; i < NONCE_SIZE; i++) {
        nonce[i] = trng_read_byte();
    }

    return 0;
}

/*
 * Build storage AAD: slot(1) || uuid(16) || group_id(2 LE) || name(32).
 * Returns STORAGE_AAD_SIZE (51).
 */
size_t build_storage_aad(uint8_t slot,
                          const uint8_t *uuid,
                          uint16_t group_id,
                          const char *name,
                          uint8_t *aad)
{
    uint8_t i;
    size_t  name_len = 0;

    /* Bounded name scan — no strlen on untrusted input.
     * Loop counter i in [0, MAX_NAME_SIZE). */
    for (i = 0; i < MAX_NAME_SIZE && name[i] != '\0'; i++) {
        name_len++;
    }

    aad[0] = slot;
    memcpy(aad + 1, uuid, UUID_SIZE);
    aad[17] = (uint8_t)(group_id & 0xFF);
    aad[18] = (uint8_t)((group_id >> 8) & 0xFF);
    memset(aad + 19, 0, 32);
    memcpy(aad + 19, name, name_len);

    return STORAGE_AAD_SIZE;
}

/*
 * Build transfer AAD: recv_chal(12) || send_chal(12) || slot(1) ||
 *                     uuid(16) || group_id(2 LE) || name(32).
 * Returns TRANSFER_AAD_SIZE (75).
 */
size_t build_transfer_aad(const uint8_t *recv_chal,
                           const uint8_t *send_chal,
                           uint8_t slot,
                           const uint8_t *uuid,
                           uint16_t group_id,
                           const char *name,
                           uint8_t *aad)
{
    uint8_t i;
    size_t  name_len = 0;

    /* Bounded name scan — loop counter i in [0, MAX_NAME_SIZE). */
    for (i = 0; i < MAX_NAME_SIZE && name[i] != '\0'; i++) {
        name_len++;
    }

    memcpy(aad,      recv_chal, NONCE_SIZE);   /* [0..11]  */
    memcpy(aad + 12, send_chal, NONCE_SIZE);   /* [12..23] */
    aad[24] = slot;                             /* [24]     */
    memcpy(aad + 25, uuid, UUID_SIZE);         /* [25..40] */
    aad[41] = (uint8_t)(group_id & 0xFF);      /* [41]     */
    aad[42] = (uint8_t)((group_id >> 8) & 0xFF); /* [42]  */
    memset(aad + 43, 0, 32);                   /* [43..74] */
    memcpy(aad + 43, name, name_len);

    return TRANSFER_AAD_SIZE;
}
