/**
 * @file crypto.c
 * @brief Cryptographic implementation for eCTF HSM
 * @date 2026
 *
 * Fix #5 (alignment): DL_AESADV_loadInputDataAligned / readOutputDataAligned
 * require 4-byte-aligned pointers.  Callers may pass pointers into #pragma
 * pack(push,1) structs (file_t, file_data_t) which are NOT guaranteed to be
 * aligned.  All data now flows through the local aligned block_in / block_out
 * buffers for every block — full and partial alike.  The Aligned suffix is
 * retained because the buffers themselves are declared __attribute__((aligned(4))).
 *
 * Fix #6 (infinite AES polling): every hardware busy-wait now has an explicit
 * iteration counter; security_halt() is called if the limit is exceeded.  This
 * prevents a permanent hang if the AESADV peripheral stalls after a glitch.
 *
 * Fix #11 (strlen on untrusted name): build_storage_aad() now uses strnlen()
 * capped at MAX_NAME_SIZE-1 rather than unbounded strlen(), so a name field
 * with no null terminator (e.g. read raw from flash) cannot walk past the
 * array.
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

/* All local buffers passed to Aligned AES API must be 4-byte aligned. */
#define ALIGNED_BUFFER __attribute__((aligned(4)))

/* Maximum AES peripheral poll iterations before security_halt(). ~100 K.
 * At 32 MHz with ~5 cycles/iteration ≈ 15 ms — far above the hardware spec. */
#define AES_POLL_LIMIT 100000UL

/*
 * Crypto Initialization — no-op; key loaded per operation from flash.
 */
int crypto_init(void)
{
    return 0;
}

/*
 * Internal: Load GCM_KEY into AESADV key registers (4-byte aligned key).
 */
static void load_key_to_aes(void)
{
    DL_AESADV_setKeyAligned(AESADV, (const uint32_t *)GCM_KEY,
                            DL_AESADV_KEY_SIZE_256_BIT);
}

/*
 * AES-256-GCM Encrypt
 *
 * plaintext → ciphertext; writes GCM tag to tag[TAG_SIZE].
 * Returns 0 on success, -1 on error.
 */
int aes_gcm_encrypt(const uint8_t *nonce,
                    const uint8_t *aad,    size_t aad_len,
                    const uint8_t *plaintext, size_t pt_len,
                    uint8_t *ciphertext,
                    uint8_t *tag)
{
    /* FIX #5: all data paths go through these aligned block buffers. */
    ALIGNED_BUFFER uint8_t iv_buf[16];
    ALIGNED_BUFFER uint8_t block_in[AES_BLOCK_SIZE];
    ALIGNED_BUFFER uint8_t block_out[AES_BLOCK_SIZE];

    size_t full_blocks, remaining, i;
    uint32_t poll_i;

    if (nonce == NULL || tag == NULL) { return -1; }
    if ((aad == NULL && aad_len > 0) || aad_len > MAX_AAD_SIZE) { return -1; }
    if ((plaintext == NULL && pt_len > 0) || pt_len > MAX_PLAINTEXT_SIZE) { return -1; }
    if (ciphertext == NULL && pt_len > 0) { return -1; }

    random_delay();

    /* IV: 12-byte nonce || 0x00000001 */
    memset(iv_buf, 0, sizeof(iv_buf));
    memcpy(iv_buf, nonce, NONCE_SIZE);
    iv_buf[15] = 0x01;

    DL_AESADV_Config gcmConfig = {
        .mode             = DL_AESADV_MODE_GCM_AUTONOMOUS,
        .direction        = DL_AESADV_DIR_ENCRYPT,
        .ctr_ctrWidth     = DL_AESADV_CTR_WIDTH_32_BIT,
        .cfb_fbWidth      = DL_AESADV_FB_WIDTH_128,
        .ccm_ctrWidth     = DL_AESADV_CCM_CTR_WIDTH_2_BYTES,
        .ccm_tagWidth     = DL_AESADV_CCM_TAG_WIDTH_1_BYTE,
        .iv               = iv_buf,
        .nonce            = NULL,
        .lowerCryptoLength = (uint32_t)pt_len,
        .upperCryptoLength = 0,
        .aadLength         = (uint32_t)aad_len,
    };

    load_key_to_aes();
    DL_AESADV_initGCM(AESADV, &gcmConfig);

    /* --- Process AAD --- */
    if (aad_len > 0) {
        full_blocks = aad_len / AES_BLOCK_SIZE;
        for (i = 0; i < full_blocks; i++) {
            /* FIX #5: copy into aligned buffer before hardware load. */
            memcpy(block_in, aad + i * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
            for (poll_i = 0; poll_i < AES_POLL_LIMIT; poll_i++) { /* FIX #6 */
                if (DL_AESADV_isInputReady(AESADV)) break;
            }
            if (poll_i >= AES_POLL_LIMIT) { security_halt(); }
            DL_AESADV_loadInputDataAligned(AESADV, (const uint32_t *)block_in);
        }
        remaining = aad_len % AES_BLOCK_SIZE;
        if (remaining > 0) {
            memset(block_in, 0, AES_BLOCK_SIZE);
            memcpy(block_in, aad + full_blocks * AES_BLOCK_SIZE, remaining);
            for (poll_i = 0; poll_i < AES_POLL_LIMIT; poll_i++) {
                if (DL_AESADV_isInputReady(AESADV)) break;
            }
            if (poll_i >= AES_POLL_LIMIT) { security_halt(); }
            DL_AESADV_loadInputDataAligned(AESADV, (const uint32_t *)block_in);
        }
    }

    /* --- Process plaintext → ciphertext --- */
    if (pt_len > 0) {
        full_blocks = pt_len / AES_BLOCK_SIZE;
        for (i = 0; i < full_blocks; i++) {
            memcpy(block_in, plaintext + i * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
            for (poll_i = 0; poll_i < AES_POLL_LIMIT; poll_i++) {
                if (DL_AESADV_isInputReady(AESADV)) break;
            }
            if (poll_i >= AES_POLL_LIMIT) { security_halt(); }
            DL_AESADV_loadInputDataAligned(AESADV, (const uint32_t *)block_in);
            for (poll_i = 0; poll_i < AES_POLL_LIMIT; poll_i++) {
                if (DL_AESADV_isOutputReady(AESADV)) break;
            }
            if (poll_i >= AES_POLL_LIMIT) { security_halt(); }
            DL_AESADV_readOutputDataAligned(AESADV, (uint32_t *)block_out);
            memcpy(ciphertext + i * AES_BLOCK_SIZE, block_out, AES_BLOCK_SIZE);
        }
        remaining = pt_len % AES_BLOCK_SIZE;
        if (remaining > 0) {
            memset(block_in, 0, AES_BLOCK_SIZE);
            memcpy(block_in, plaintext + full_blocks * AES_BLOCK_SIZE, remaining);
            for (poll_i = 0; poll_i < AES_POLL_LIMIT; poll_i++) {
                if (DL_AESADV_isInputReady(AESADV)) break;
            }
            if (poll_i >= AES_POLL_LIMIT) { security_halt(); }
            DL_AESADV_loadInputDataAligned(AESADV, (const uint32_t *)block_in);
            for (poll_i = 0; poll_i < AES_POLL_LIMIT; poll_i++) {
                if (DL_AESADV_isOutputReady(AESADV)) break;
            }
            if (poll_i >= AES_POLL_LIMIT) { security_halt(); }
            DL_AESADV_readOutputDataAligned(AESADV, (uint32_t *)block_out);
            memcpy(ciphertext + full_blocks * AES_BLOCK_SIZE, block_out, remaining);
        }
    }

    /* --- Read GCM tag --- */
    ALIGNED_BUFFER uint8_t tag_buf[TAG_SIZE];
    for (poll_i = 0; poll_i < AES_POLL_LIMIT; poll_i++) {
        if (DL_AESADV_isSavedOutputContextReady(AESADV)) break;
    }
    if (poll_i >= AES_POLL_LIMIT) { security_halt(); }
    DL_AESADV_readTAGAligned(AESADV, (uint32_t *)tag_buf);
    memcpy(tag, tag_buf, TAG_SIZE);

    return 0;
}

/*
 * AES-256-GCM Decrypt
 *
 * ciphertext → plaintext; verifies GCM tag (constant-time).
 * Zeros plaintext on tag mismatch or any error.
 * Returns 0 on success, -1 on failure.
 */
int aes_gcm_decrypt(const uint8_t *nonce,
                    const uint8_t *aad,    size_t aad_len,
                    const uint8_t *ciphertext, size_t ct_len,
                    const uint8_t *tag,
                    uint8_t *plaintext)
{
    ALIGNED_BUFFER uint8_t iv_buf[16];
    ALIGNED_BUFFER uint8_t block_in[AES_BLOCK_SIZE];
    ALIGNED_BUFFER uint8_t block_out[AES_BLOCK_SIZE];
    ALIGNED_BUFFER uint8_t computed_tag[TAG_SIZE];

    size_t full_blocks, remaining, i;
    uint32_t poll_i;

    if (nonce == NULL || tag == NULL) { return -1; }
    if ((aad == NULL && aad_len > 0) || aad_len > MAX_AAD_SIZE) { return -1; }
    if ((ciphertext == NULL && ct_len > 0) || ct_len > MAX_PLAINTEXT_SIZE) { return -1; }
    if (plaintext == NULL && ct_len > 0) { return -1; }

    random_delay();

    memset(iv_buf, 0, sizeof(iv_buf));
    memcpy(iv_buf, nonce, NONCE_SIZE);
    iv_buf[15] = 0x01;

    DL_AESADV_Config gcmConfig = {
        .mode             = DL_AESADV_MODE_GCM_AUTONOMOUS,
        .direction        = DL_AESADV_DIR_DECRYPT,
        .ctr_ctrWidth     = DL_AESADV_CTR_WIDTH_32_BIT,
        .cfb_fbWidth      = DL_AESADV_FB_WIDTH_128,
        .ccm_ctrWidth     = DL_AESADV_CCM_CTR_WIDTH_2_BYTES,
        .ccm_tagWidth     = DL_AESADV_CCM_TAG_WIDTH_1_BYTE,
        .iv               = iv_buf,
        .nonce            = NULL,
        .lowerCryptoLength = (uint32_t)ct_len,
        .upperCryptoLength = 0,
        .aadLength         = (uint32_t)aad_len,
    };

    load_key_to_aes();
    DL_AESADV_initGCM(AESADV, &gcmConfig);

    /* --- Process AAD --- */
    if (aad_len > 0) {
        full_blocks = aad_len / AES_BLOCK_SIZE;
        for (i = 0; i < full_blocks; i++) {
            memcpy(block_in, aad + i * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
            for (poll_i = 0; poll_i < AES_POLL_LIMIT; poll_i++) {
                if (DL_AESADV_isInputReady(AESADV)) break;
            }
            if (poll_i >= AES_POLL_LIMIT) { security_halt(); }
            DL_AESADV_loadInputDataAligned(AESADV, (const uint32_t *)block_in);
        }
        remaining = aad_len % AES_BLOCK_SIZE;
        if (remaining > 0) {
            memset(block_in, 0, AES_BLOCK_SIZE);
            memcpy(block_in, aad + full_blocks * AES_BLOCK_SIZE, remaining);
            for (poll_i = 0; poll_i < AES_POLL_LIMIT; poll_i++) {
                if (DL_AESADV_isInputReady(AESADV)) break;
            }
            if (poll_i >= AES_POLL_LIMIT) { security_halt(); }
            DL_AESADV_loadInputDataAligned(AESADV, (const uint32_t *)block_in);
        }
    }

    /* --- Process ciphertext → plaintext --- */
    if (ct_len > 0) {
        full_blocks = ct_len / AES_BLOCK_SIZE;
        for (i = 0; i < full_blocks; i++) {
            memcpy(block_in, ciphertext + i * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
            for (poll_i = 0; poll_i < AES_POLL_LIMIT; poll_i++) {
                if (DL_AESADV_isInputReady(AESADV)) break;
            }
            if (poll_i >= AES_POLL_LIMIT) { security_halt(); }
            DL_AESADV_loadInputDataAligned(AESADV, (const uint32_t *)block_in);
            for (poll_i = 0; poll_i < AES_POLL_LIMIT; poll_i++) {
                if (DL_AESADV_isOutputReady(AESADV)) break;
            }
            if (poll_i >= AES_POLL_LIMIT) { security_halt(); }
            DL_AESADV_readOutputDataAligned(AESADV, (uint32_t *)block_out);
            memcpy(plaintext + i * AES_BLOCK_SIZE, block_out, AES_BLOCK_SIZE);
        }
        remaining = ct_len % AES_BLOCK_SIZE;
        if (remaining > 0) {
            memset(block_in, 0, AES_BLOCK_SIZE);
            memcpy(block_in, ciphertext + full_blocks * AES_BLOCK_SIZE, remaining);
            for (poll_i = 0; poll_i < AES_POLL_LIMIT; poll_i++) {
                if (DL_AESADV_isInputReady(AESADV)) break;
            }
            if (poll_i >= AES_POLL_LIMIT) { security_halt(); }
            DL_AESADV_loadInputDataAligned(AESADV, (const uint32_t *)block_in);
            for (poll_i = 0; poll_i < AES_POLL_LIMIT; poll_i++) {
                if (DL_AESADV_isOutputReady(AESADV)) break;
            }
            if (poll_i >= AES_POLL_LIMIT) { security_halt(); }
            DL_AESADV_readOutputDataAligned(AESADV, (uint32_t *)block_out);
            memcpy(plaintext + full_blocks * AES_BLOCK_SIZE, block_out, remaining);
        }
    }

    /* --- Read and verify computed tag (constant-time) --- */
    for (poll_i = 0; poll_i < AES_POLL_LIMIT; poll_i++) {
        if (DL_AESADV_isSavedOutputContextReady(AESADV)) break;
    }
    if (poll_i >= AES_POLL_LIMIT) { security_halt(); }
    DL_AESADV_readTAGAligned(AESADV, (uint32_t *)computed_tag);

    if (!secure_compare(computed_tag, tag, TAG_SIZE)) {
        secure_zero(plaintext, ct_len);
        return -1;
    }

    return 0;
}

/*
 * HMAC-SHA256 with mandatory domain separator.
 * Computes HMAC(key, data || domain).
 */
int hmac_sha256(const uint8_t *key,
                const uint8_t *data, size_t data_len,
                const char    *domain,
                uint8_t       *output)
{
    Hmac   hmac;
    int    ret;
    size_t domain_len;

    if (key == NULL || domain == NULL || output == NULL) { return -1; }
    if (data == NULL && data_len > 0) { return -1; }

    domain_len = strlen(domain);

    ret = wc_HmacSetKey(&hmac, WC_SHA256, key, AUTH_KEY_SIZE);
    if (ret != 0) { return -1; }

    if (data_len > 0) {
        ret = wc_HmacUpdate(&hmac, data, (word32)data_len);
        if (ret != 0) { return -1; }
    }

    ret = wc_HmacUpdate(&hmac, (const uint8_t *)domain, (word32)domain_len);
    if (ret != 0) { return -1; }

    ret = wc_HmacFinal(&hmac, output);
    if (ret != 0) { return -1; }

    return 0;
}

/*
 * HMAC verification — constant-time, glitch-resistant.
 * Double-computes with random delay between passes; halts on mismatch.
 */
bool hmac_verify(const uint8_t *key,
                 const uint8_t *data, size_t data_len,
                 const char    *domain,
                 const uint8_t *expected_mac)
{
    uint8_t mac1[HMAC_SIZE];
    uint8_t mac2[HMAC_SIZE];
    volatile bool match1;
    volatile bool match2;

    if (hmac_sha256(key, data, data_len, domain, mac1) != 0) {
        secure_zero(mac1, HMAC_SIZE);
        return false;
    }
    match1 = secure_compare(mac1, expected_mac, HMAC_SIZE);

    random_delay();

    if (hmac_sha256(key, data, data_len, domain, mac2) != 0) {
        secure_zero(mac1, HMAC_SIZE);
        secure_zero(mac2, HMAC_SIZE);
        return false;
    }
    match2 = secure_compare(mac2, expected_mac, HMAC_SIZE);

    if (match1 != match2) {
        secure_zero(mac1, HMAC_SIZE);
        secure_zero(mac2, HMAC_SIZE);
        security_halt();
    }

    secure_zero(mac1, HMAC_SIZE);
    secure_zero(mac2, HMAC_SIZE);

    return match1;
}

/*
 * Generate 12-byte random nonce from hardware TRNG.
 */
int generate_nonce(uint8_t *nonce)
{
    size_t i;

    if (nonce == NULL) { return -1; }

    for (i = 0; i < NONCE_SIZE; i++) {
        nonce[i] = trng_read_byte();
    }

    return 0;
}

/*
 * Build AAD for file storage.
 * Layout: slot(1) || uuid(16) || group_id(2 LE) || name(32 zero-padded) = 51 bytes.
 *
 * FIX #11: uses strnlen(name, MAX_NAME_SIZE - 1) instead of strlen(name).
 * A name field read raw from flash may not have a null terminator; unbounded
 * strlen() would walk past the array boundary into adjacent memory.
 */
size_t build_storage_aad(uint8_t slot,
                         const uint8_t *uuid,
                         uint16_t group_id,
                         const char *name,
                         uint8_t *aad)
{
    size_t offset   = 0;
    size_t name_len = 0;

    aad[offset++] = slot;

    memcpy(aad + offset, uuid, 16);
    offset += 16;

    aad[offset++] = (uint8_t)(group_id & 0xFF);
    aad[offset++] = (uint8_t)((group_id >> 8) & 0xFF);

    /* Zero-pad the 32-byte name field, then overlay up to 31 name bytes. */
    memset(aad + offset, 0, 32);
    if (name != NULL) {
        /* FIX #11: manual bounded scan — TI clang C99 does not expose strnlen.
         * Caps at MAX_NAME_SIZE-1 so a non-null-terminated name (e.g. read raw
         * from flash) cannot walk past the array boundary. */
        for (name_len = 0; name_len < (MAX_NAME_SIZE - 1); name_len++) {
            if (name[name_len] == '\0') break;
        }
        memcpy(aad + offset, name, name_len);
    }
    offset += 32;

    return offset; /* 51 */
}

/*
 * Build AAD for file transfer.
 * Layout: recv_chal(12) || send_chal(12) || slot(1) || uuid(16) || group_id(2 LE) = 43 bytes.
 */
size_t build_transfer_aad(const uint8_t *receiver_challenge,
                          const uint8_t *sender_challenge,
                          uint8_t slot,
                          const uint8_t *uuid,
                          uint16_t group_id,
                          uint8_t *aad)
{
    size_t offset = 0;

    memcpy(aad + offset, receiver_challenge, 12);
    offset += 12;

    memcpy(aad + offset, sender_challenge, 12);
    offset += 12;

    aad[offset++] = slot;

    memcpy(aad + offset, uuid, 16);
    offset += 16;

    aad[offset++] = (uint8_t)(group_id & 0xFF);
    aad[offset++] = (uint8_t)((group_id >> 8) & 0xFF);

    return offset; /* 43 */
}
