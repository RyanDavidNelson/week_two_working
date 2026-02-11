/**
 * @file crypto.c
 * @brief Cryptographic implementation for eCTF HSM
 * @date 2026
 * @copyright Copyright (c) 2026 The MITRE Corporation
 *
 * Two-key architecture:
 * - GCM_KEY (KEYSTORE slot 0): AES-256-GCM via hardware AESADV
 * - AUTH_KEY (flash): HMAC-SHA256 via wolfcrypt
 *
 * Security features:
 * - Hardware GCM tag verification (constant-time)
 * - Double-computation for glitch/fault resistance
 * - Random delays between security-critical operations
 */

#include "crypto.h"
#include "security.h"
#include "secrets.h"
#include "ti_msp_dl_config.h"
#include <ti/driverlib/dl_aesadv.h>
#include <ti/driverlib/dl_keystorectl.h>
#include <ti/devices/msp/msp.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <string.h>

/* Alignment macro for DMA/hardware buffers */
#define ALIGNED_BUFFER __attribute__((aligned(4)))

/*
 * KEYSTORE configuration for writing 256-bit key
 */
static DL_KEYSTORECTL_KeyWrConfig gKeyWriteConfig = {
    .keySlot = DL_KEYSTORECTL_KEY_SLOT_0,
    .keySize = DL_KEYSTORECTL_KEY_SIZE_256_BITS,
    .key = NULL  /* Set at runtime */
};

/*
 * KEYSTORE configuration for transferring key to AES engine
 */
static DL_KEYSTORECTL_Config gKeyTransferConfig = {
    .keySlot = DL_KEYSTORECTL_KEY_SLOT_0,
    .keySize = DL_KEYSTORECTL_KEY_SIZE_256_BITS,
    .cryptoSel = DL_KEYSTORECTL_CRYPTO_SEL_AES
};

/*
 * Crypto Initialization - Load GCM key into KEYSTORE
 */
int crypto_init(void)
{
    /* Set key pointer */
    gKeyWriteConfig.key = (uint32_t *)GCM_KEY;
    
    /* Write GCM_KEY to KEYSTORE slot 0 */
    DL_KEYSTORECTL_writeKey(KEYSTORECTL, &gKeyWriteConfig);
    
    return CRYPTO_OK;
}

/*
 * Internal: Transfer key from KEYSTORE to AES engine
 */
static void transfer_key_to_aes(void)
{
    DL_KEYSTORECTL_transferKey(KEYSTORECTL, &gKeyTransferConfig);
}

/*
 * Internal: Single AES-GCM encrypt pass (no glitch protection)
 */
static int aes_gcm_encrypt_single(const uint8_t *nonce,
                                  const uint8_t *aad, size_t aad_len,
                                  const uint8_t *plaintext, size_t pt_len,
                                  uint8_t *ciphertext,
                                  uint8_t *tag)
{
    size_t i;
    size_t full_blocks;
    size_t remaining;
    ALIGNED_BUFFER uint8_t iv_buf[16];
    ALIGNED_BUFFER uint8_t padded[AES_BLOCK_SIZE];
    ALIGNED_BUFFER uint8_t out_padded[AES_BLOCK_SIZE];
    
    /* Build IV: 12-byte nonce + 4-byte counter (starts at 1 for GCM) */
    memset(iv_buf, 0, 16);
    memcpy(iv_buf, nonce, NONCE_SIZE);
    iv_buf[15] = 0x01;  /* GCM counter starts at 1 */
    
    /* Configure GCM operation */
    DL_AESADV_Config gcmConfig = {
        .mode = DL_AESADV_MODE_GCM_AUTONOMOUS,
        .direction = DL_AESADV_DIR_ENCRYPT,
        .ctr_ctrWidth = DL_AESADV_CTR_WIDTH_32_BIT,
        .cfb_fbWidth = DL_AESADV_FB_WIDTH_128,
        .ccm_ctrWidth = DL_AESADV_CCM_CTR_WIDTH_2_BYTES,
        .ccm_tagWidth = DL_AESADV_CCM_TAG_WIDTH_1_BYTE,
        .iv = iv_buf,
        .nonce = NULL,
        .lowerCryptoLength = (uint32_t)pt_len,
        .upperCryptoLength = 0,
        .aadLength = (uint32_t)aad_len
    };
    
    /* Set key size and transfer from KEYSTORE */
    DL_AESADV_setKeySize(AESADV, DL_AESADV_KEY_SIZE_256_BIT);
    transfer_key_to_aes();
    
    /* Initialize GCM mode */
    DL_AESADV_initGCM(AESADV, &gcmConfig);
    
    /* Process AAD if present */
    if (aad_len > 0) {
        full_blocks = aad_len / AES_BLOCK_SIZE;
        
        /* Full AAD blocks */
        for (i = 0; i < full_blocks; i++) {
            while (!DL_AESADV_isInputReady(AESADV)) { }
            DL_AESADV_loadInputDataAligned(AESADV, 
                (const uint32_t *)(aad + i * AES_BLOCK_SIZE));
        }
        
        /* Partial AAD block (zero-padded) */
        remaining = aad_len % AES_BLOCK_SIZE;
        if (remaining > 0) {
            memset(padded, 0, AES_BLOCK_SIZE);
            memcpy(padded, aad + full_blocks * AES_BLOCK_SIZE, remaining);
            while (!DL_AESADV_isInputReady(AESADV)) { }
            DL_AESADV_loadInputDataAligned(AESADV, (const uint32_t *)padded);
        }
    }
    
    /* Process plaintext → ciphertext */
    if (pt_len > 0) {
        full_blocks = pt_len / AES_BLOCK_SIZE;
        
        /* Full plaintext blocks */
        for (i = 0; i < full_blocks; i++) {
            while (!DL_AESADV_isInputReady(AESADV)) { }
            DL_AESADV_loadInputDataAligned(AESADV, 
                (const uint32_t *)(plaintext + i * AES_BLOCK_SIZE));
            while (!DL_AESADV_isOutputReady(AESADV)) { }
            DL_AESADV_readOutputDataAligned(AESADV, 
                (uint32_t *)(ciphertext + i * AES_BLOCK_SIZE));
        }
        
        /* Partial plaintext block */
        remaining = pt_len % AES_BLOCK_SIZE;
        if (remaining > 0) {
            memset(padded, 0, AES_BLOCK_SIZE);
            memcpy(padded, plaintext + full_blocks * AES_BLOCK_SIZE, remaining);
            while (!DL_AESADV_isInputReady(AESADV)) { }
            DL_AESADV_loadInputDataAligned(AESADV, (const uint32_t *)padded);
            while (!DL_AESADV_isOutputReady(AESADV)) { }
            DL_AESADV_readOutputDataAligned(AESADV, (uint32_t *)out_padded);
            memcpy(ciphertext + full_blocks * AES_BLOCK_SIZE, out_padded, remaining);
        }
    }
    
    /* Wait for tag to be ready and read it */
    while (!DL_AESADV_isSavedOutputContextReady(AESADV)) { }
    DL_AESADV_readTAGAligned(AESADV, (uint32_t *)tag);
    
    return CRYPTO_OK;
}

/*
 * Internal: Single AES-GCM decrypt pass (no glitch protection)
 * Returns CRYPTO_OK if tag matches, CRYPTO_ERR_TAG otherwise
 */
static int aes_gcm_decrypt_single(const uint8_t *nonce,
                                  const uint8_t *aad, size_t aad_len,
                                  const uint8_t *ciphertext, size_t ct_len,
                                  const uint8_t *expected_tag,
                                  uint8_t *plaintext)
{
    size_t i;
    size_t full_blocks;
    size_t remaining;
    ALIGNED_BUFFER uint8_t iv_buf[16];
    ALIGNED_BUFFER uint8_t padded[AES_BLOCK_SIZE];
    ALIGNED_BUFFER uint8_t out_padded[AES_BLOCK_SIZE];
    ALIGNED_BUFFER uint8_t computed_tag[TAG_SIZE];
    
    /* Build IV: 12-byte nonce + 4-byte counter */
    memset(iv_buf, 0, 16);
    memcpy(iv_buf, nonce, NONCE_SIZE);
    iv_buf[15] = 0x01;
    
    /* Configure GCM decryption */
    DL_AESADV_Config gcmConfig = {
        .mode = DL_AESADV_MODE_GCM_AUTONOMOUS,
        .direction = DL_AESADV_DIR_DECRYPT,
        .ctr_ctrWidth = DL_AESADV_CTR_WIDTH_32_BIT,
        .cfb_fbWidth = DL_AESADV_FB_WIDTH_128,
        .ccm_ctrWidth = DL_AESADV_CCM_CTR_WIDTH_2_BYTES,
        .ccm_tagWidth = DL_AESADV_CCM_TAG_WIDTH_1_BYTE,
        .iv = iv_buf,
        .nonce = NULL,
        .lowerCryptoLength = (uint32_t)ct_len,
        .upperCryptoLength = 0,
        .aadLength = (uint32_t)aad_len
    };
    
    /* Set key size and transfer from KEYSTORE */
    DL_AESADV_setKeySize(AESADV, DL_AESADV_KEY_SIZE_256_BIT);
    transfer_key_to_aes();
    
    /* Initialize GCM mode */
    DL_AESADV_initGCM(AESADV, &gcmConfig);
    
    /* Process AAD if present */
    if (aad_len > 0) {
        full_blocks = aad_len / AES_BLOCK_SIZE;
        
        for (i = 0; i < full_blocks; i++) {
            while (!DL_AESADV_isInputReady(AESADV)) { }
            DL_AESADV_loadInputDataAligned(AESADV, 
                (const uint32_t *)(aad + i * AES_BLOCK_SIZE));
        }
        
        remaining = aad_len % AES_BLOCK_SIZE;
        if (remaining > 0) {
            memset(padded, 0, AES_BLOCK_SIZE);
            memcpy(padded, aad + full_blocks * AES_BLOCK_SIZE, remaining);
            while (!DL_AESADV_isInputReady(AESADV)) { }
            DL_AESADV_loadInputDataAligned(AESADV, (const uint32_t *)padded);
        }
    }
    
    /* Process ciphertext → plaintext */
    if (ct_len > 0) {
        full_blocks = ct_len / AES_BLOCK_SIZE;
        
        for (i = 0; i < full_blocks; i++) {
            while (!DL_AESADV_isInputReady(AESADV)) { }
            DL_AESADV_loadInputDataAligned(AESADV, 
                (const uint32_t *)(ciphertext + i * AES_BLOCK_SIZE));
            while (!DL_AESADV_isOutputReady(AESADV)) { }
            DL_AESADV_readOutputDataAligned(AESADV, 
                (uint32_t *)(plaintext + i * AES_BLOCK_SIZE));
        }
        
        remaining = ct_len % AES_BLOCK_SIZE;
        if (remaining > 0) {
            memset(padded, 0, AES_BLOCK_SIZE);
            memcpy(padded, ciphertext + full_blocks * AES_BLOCK_SIZE, remaining);
            while (!DL_AESADV_isInputReady(AESADV)) { }
            DL_AESADV_loadInputDataAligned(AESADV, (const uint32_t *)padded);
            while (!DL_AESADV_isOutputReady(AESADV)) { }
            DL_AESADV_readOutputDataAligned(AESADV, (uint32_t *)out_padded);
            memcpy(plaintext + full_blocks * AES_BLOCK_SIZE, out_padded, remaining);
        }
    }
    
    /* Read computed tag */
    while (!DL_AESADV_isSavedOutputContextReady(AESADV)) { }
    DL_AESADV_readTAGAligned(AESADV, (uint32_t *)computed_tag);
    
    /* Constant-time tag comparison */
    if (!secure_compare(computed_tag, expected_tag, TAG_SIZE)) {
        /* Tag mismatch - zero plaintext and return error */
        secure_zero(plaintext, ct_len);
        return CRYPTO_ERR_TAG;
    }
    
    return CRYPTO_OK;
}

/*
 * AES-256-GCM Encrypt with Double-Computation Protection
 */
int aes_gcm_encrypt(const uint8_t *nonce,
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *plaintext, size_t pt_len,
                    uint8_t *ciphertext,
                    uint8_t *tag)
{
    ALIGNED_BUFFER uint8_t ciphertext2[MAX_PLAINTEXT_SIZE];
    ALIGNED_BUFFER uint8_t tag2[TAG_SIZE];
    int result1, result2;
    bool ct_match, tag_match;
    
    /* Parameter validation */
    if (nonce == NULL || tag == NULL) {
        return CRYPTO_ERR_PARAM;
    }
    if ((aad == NULL && aad_len > 0) || aad_len > MAX_AAD_SIZE) {
        return CRYPTO_ERR_PARAM;
    }
    if ((plaintext == NULL && pt_len > 0) || pt_len > MAX_PLAINTEXT_SIZE) {
        return CRYPTO_ERR_LENGTH;
    }
    if (ciphertext == NULL && pt_len > 0) {
        return CRYPTO_ERR_PARAM;
    }
    
    /* Random delay before first computation */
    random_delay();
    
    /* First encryption pass */
    result1 = aes_gcm_encrypt_single(nonce, aad, aad_len, plaintext, pt_len, 
                                      ciphertext, tag);
    if (result1 != CRYPTO_OK) {
        return result1;
    }
    
    /* Random delay between computations */
    random_delay();
    
    /* Second encryption pass to separate buffers */
    result2 = aes_gcm_encrypt_single(nonce, aad, aad_len, plaintext, pt_len, 
                                      ciphertext2, tag2);
    
    /* Constant-time comparisons */
    ct_match = (pt_len == 0) || secure_compare(ciphertext, ciphertext2, pt_len);
    tag_match = secure_compare(tag, tag2, TAG_SIZE);
    
    /* Clear verification buffers */
    secure_zero(ciphertext2, pt_len);
    secure_zero(tag2, TAG_SIZE);
    
    /* Random delay before decision */
    random_delay();
    
    /* Glitch detection - halt if computations differ */
    if (result2 != CRYPTO_OK || !ct_match || !tag_match) {
        secure_zero(ciphertext, pt_len);
        secure_zero(tag, TAG_SIZE);
        security_halt();
        /* Never returns */
    }
    
    return CRYPTO_OK;
}

/*
 * AES-256-GCM Decrypt with Double-Computation Protection
 */
int aes_gcm_decrypt(const uint8_t *nonce,
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *ciphertext, size_t ct_len,
                    const uint8_t *tag,
                    uint8_t *plaintext)
{
    ALIGNED_BUFFER uint8_t plaintext2[MAX_PLAINTEXT_SIZE];
    int result1, result2;
    bool pt_match;
    
    /* Parameter validation */
    if (nonce == NULL || tag == NULL) {
        return CRYPTO_ERR_PARAM;
    }
    if ((aad == NULL && aad_len > 0) || aad_len > MAX_AAD_SIZE) {
        return CRYPTO_ERR_PARAM;
    }
    if ((ciphertext == NULL && ct_len > 0) || ct_len > MAX_PLAINTEXT_SIZE) {
        return CRYPTO_ERR_LENGTH;
    }
    if (plaintext == NULL && ct_len > 0) {
        return CRYPTO_ERR_PARAM;
    }
    
    /* Random delay before first computation */
    random_delay();
    
    /* First decryption pass */
    result1 = aes_gcm_decrypt_single(nonce, aad, aad_len, ciphertext, ct_len, 
                                      tag, plaintext);
    
    /* Random delay between computations */
    random_delay();
    
    /* Second decryption pass to separate buffer */
    result2 = aes_gcm_decrypt_single(nonce, aad, aad_len, ciphertext, ct_len, 
                                      tag, plaintext2);
    
    /* Constant-time comparison (only if first succeeded) */
    pt_match = (ct_len == 0) || secure_compare(plaintext, plaintext2, ct_len);
    
    /* Clear verification buffer */
    secure_zero(plaintext2, ct_len);
    
    /* Random delay before decision */
    random_delay();
    
    /* Check for tag verification failure */
    if (result1 == CRYPTO_ERR_TAG) {
        /* Tag failed - plaintext already zeroed by decrypt_single */
        return CRYPTO_ERR_TAG;
    }
    
    /* Glitch detection - halt if computations differ */
    if (result1 != result2 || !pt_match) {
        secure_zero(plaintext, ct_len);
        security_halt();
        /* Never returns */
    }
    
    return CRYPTO_OK;
}

/*
 * HMAC-SHA256 using wolfcrypt
 */
int hmac_sha256(const uint8_t *key,
                const uint8_t *data, size_t data_len,
                uint8_t *output)
{
    Hmac hmac;
    int ret;
    
    /* Parameter validation */
    if (key == NULL || output == NULL) {
        return CRYPTO_ERR_PARAM;
    }
    if (data == NULL && data_len > 0) {
        return CRYPTO_ERR_PARAM;
    }
    
    /* Initialize HMAC with key */
    ret = wc_HmacSetKey(&hmac, WC_SHA256, key, AUTH_KEY_SIZE);
    if (ret != 0) {
        return CRYPTO_ERR_HMAC;
    }
    
    /* Process data */
    if (data_len > 0) {
        ret = wc_HmacUpdate(&hmac, data, (word32)data_len);
        if (ret != 0) {
            return CRYPTO_ERR_HMAC;
        }
    }
    
    /* Finalize */
    ret = wc_HmacFinal(&hmac, output);
    if (ret != 0) {
        return CRYPTO_ERR_HMAC;
    }
    
    return CRYPTO_OK;
}

/*
 * HMAC-SHA256 with domain separator
 */
int hmac_sha256_domain(const uint8_t *key,
                       const uint8_t *data, size_t data_len,
                       const char *domain,
                       uint8_t *output)
{
    Hmac hmac;
    int ret;
    size_t domain_len;
    
    /* Parameter validation */
    if (key == NULL || domain == NULL || output == NULL) {
        return CRYPTO_ERR_PARAM;
    }
    if (data == NULL && data_len > 0) {
        return CRYPTO_ERR_PARAM;
    }
    
    domain_len = strlen(domain);
    
    /* Initialize HMAC with key */
    ret = wc_HmacSetKey(&hmac, WC_SHA256, key, AUTH_KEY_SIZE);
    if (ret != 0) {
        return CRYPTO_ERR_HMAC;
    }
    
    /* Process data first */
    if (data_len > 0) {
        ret = wc_HmacUpdate(&hmac, data, (word32)data_len);
        if (ret != 0) {
            return CRYPTO_ERR_HMAC;
        }
    }
    
    /* Append domain separator */
    ret = wc_HmacUpdate(&hmac, (const uint8_t *)domain, (word32)domain_len);
    if (ret != 0) {
        return CRYPTO_ERR_HMAC;
    }
    
    /* Finalize */
    ret = wc_HmacFinal(&hmac, output);
    if (ret != 0) {
        return CRYPTO_ERR_HMAC;
    }
    
    return CRYPTO_OK;
}

/*
 * HMAC Verification (constant-time)
 */
bool hmac_verify(const uint8_t *key,
                 const uint8_t *data, size_t data_len,
                 const uint8_t *expected_mac)
{
    uint8_t computed_mac[HMAC_SIZE];
    bool match;
    
    if (hmac_sha256(key, data, data_len, computed_mac) != CRYPTO_OK) {
        secure_zero(computed_mac, HMAC_SIZE);
        return false;
    }
    
    match = secure_compare(computed_mac, expected_mac, HMAC_SIZE);
    secure_zero(computed_mac, HMAC_SIZE);
    
    return match;
}

/*
 * HMAC Verification with domain separator (constant-time)
 */
bool hmac_verify_domain(const uint8_t *key,
                        const uint8_t *data, size_t data_len,
                        const char *domain,
                        const uint8_t *expected_mac)
{
    uint8_t computed_mac[HMAC_SIZE];
    bool match;
    
    if (hmac_sha256_domain(key, data, data_len, domain, computed_mac) != CRYPTO_OK) {
        secure_zero(computed_mac, HMAC_SIZE);
        return false;
    }
    
    match = secure_compare(computed_mac, expected_mac, HMAC_SIZE);
    secure_zero(computed_mac, HMAC_SIZE);
    
    return match;
}

/*
 * Generate random nonce using hardware TRNG
 */
int generate_nonce(uint8_t *nonce)
{
    size_t i;
    
    if (nonce == NULL) {
        return CRYPTO_ERR_PARAM;
    }
    
    /* Read 12 random bytes from TRNG */
    for (i = 0; i < NONCE_SIZE; i++) {
        nonce[i] = trng_read_byte();
    }
    
    return CRYPTO_OK;
}

/*
 * Build AAD for file storage
 * Format: slot(1) || uuid(16) || group_id(2) || name(32) = 51 bytes
 */
size_t build_storage_aad(uint8_t slot,
                         const uint8_t *uuid,
                         uint16_t group_id,
                         const char *name,
                         uint8_t *aad)
{
    size_t offset = 0;
    
    /* Slot (1 byte) */
    aad[offset++] = slot;
    
    /* UUID (16 bytes) */
    memcpy(aad + offset, uuid, 16);
    offset += 16;
    
    /* Group ID (2 bytes, little-endian) */
    aad[offset++] = (uint8_t)(group_id & 0xFF);
    aad[offset++] = (uint8_t)((group_id >> 8) & 0xFF);
    
    /* Name (32 bytes, null-padded) */
    memset(aad + offset, 0, 32);
    if (name != NULL) {
        size_t name_len = strlen(name);
        if (name_len > 31) {
            name_len = 31;
        }
        memcpy(aad + offset, name, name_len);
    }
    offset += 32;
    
    return offset;  /* 51 */
}

/*
 * Build AAD for file transfer
 * Format: recv_chal(12) || send_chal(12) || slot(1) || uuid(16) || group_id(2) = 43 bytes
 */
size_t build_transfer_aad(const uint8_t *receiver_challenge,
                          const uint8_t *sender_challenge,
                          uint8_t slot,
                          const uint8_t *uuid,
                          uint16_t group_id,
                          uint8_t *aad)
{
    size_t offset = 0;
    
    /* Receiver challenge (12 bytes) */
    memcpy(aad + offset, receiver_challenge, 12);
    offset += 12;
    
    /* Sender challenge (12 bytes) */
    memcpy(aad + offset, sender_challenge, 12);
    offset += 12;
    
    /* Slot (1 byte) */
    aad[offset++] = slot;
    
    /* UUID (16 bytes) */
    memcpy(aad + offset, uuid, 16);
    offset += 16;
    
    /* Group ID (2 bytes, little-endian) */
    aad[offset++] = (uint8_t)(group_id & 0xFF);
    aad[offset++] = (uint8_t)((group_id >> 8) & 0xFF);
    
    return offset;  /* 43 */
}
