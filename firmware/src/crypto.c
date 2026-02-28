/**
 * @file crypto.c
 * @brief Cryptographic implementation for eCTF HSM
 * @date 2026
 *
 * AES-256-GCM: MSPM0L2228 AESADV hardware peripheral, CPU-polling mode.
 * HMAC-SHA256:  wolfcrypt (hardware has no HMAC accelerator).
 *
 * AESADV GCM mode: DL_AESADV_MODE_GCM_AUTONOMOUS.
 *   The hardware derives the GHASH subkey H = AES_K(0) and computes
 *   Y0-encrypted internally, so no separate ECB pass is required.
 *   Key is loaded once per call, then the peripheral is reset to clear
 *   key registers before returning — limits exposure in hardware registers.
 *
 * IV layout for a 96-bit nonce (standard GCM J0):
 *   iv[0..11]  = nonce (copied from caller)
 *   iv[12..14] = 0x00
 *   iv[15]     = 0x01  ← counter = 1 (big-endian byte order)
 *   The ARM reads iv[12..15] as a little-endian uint32, giving IV3 = 0x01000000.
 *   The TRM note "upper word iv[127:96] must be 0x01000000" refers to this value.
 *
 * Data path (CPU polling, DMA disabled):
 *   For each 16-byte block, poll isInputReady() then write 4 words.
 *   AAD blocks: no output read.
 *   Crypto blocks: after writing, poll isOutputReady() then read 4 words.
 *   Partial last block: zero-padded on input; only valid bytes copied from output.
 *   After all data: poll isSavedOutputContextReady(), read 16-byte TAG.
 *
 * SCA: random_delay() before key load; peripheral reset clears key registers.
 *
 * Include order: wolfssl headers first so settings.h resolves CFLAGS defines
 * before hmac.h applies its conditional guards.
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/hmac.h>

#include "ti/driverlib/dl_aesadv.h"
#include "crypto.h"
#include "security.h"
#include "secrets.h"
#include <string.h>


/* -----------------------------------------------------------------------
 * AESADV constants
 * ---------------------------------------------------------------------- */
#define AES_BLOCK_WORDS     4U          /* 128-bit block = 4 × uint32_t       */
#define AES_BLOCK_BYTES     16U         /* 128-bit block = 16 bytes            */

/*
 * Poll budget per block: AES-256 takes ~81 cycles (~2.5 µs at 32 MHz).
 * 100 000 iterations ≈ 3 ms at -O0 — far above any real hardware latency.
 * security_halt() fires on timeout to prevent silent hangs.
 */
#define AESADV_POLL_LIMIT   100000U


/* -----------------------------------------------------------------------
 * aesadv_reset_and_enable — power-enable, hardware-reset, then wait for
 * the context-writeable flag before returning.
 *
 * DL_AESADV_reset() self-clears within ~2 PCLK cycles, but CNTXT_RDY in
 * the CTRL register is not guaranteed asserted by the time the CPU reaches
 * the next instruction. Writing the key or CTRL before CNTXT_RDY=1 causes
 * the peripheral to silently reject the write and never assert INPUT_RDY,
 * which exhausts poll_input_ready() and triggers security_halt().
 *
 * Pattern taken directly from aesadv_ecb_256_encrypt TI SDK example.
 * ---------------------------------------------------------------------- */
static void aesadv_reset_and_enable(void)
{
    uint32_t poll_i;

    /* Power enable — idempotent if already on. */
    AESADV->GPRCM.PWREN =
        (AESADV_PWREN_KEY_UNLOCK_W | AESADV_PWREN_ENABLE_ENABLE);

    /* Hardware reset — clears CTRL, key registers, IV, TAG, DMA_HS. */
    DL_AESADV_reset(AESADV);

    /* Wait for context to become writeable before any key/config writes.
     * Loop counter poll_i in [0, AESADV_POLL_LIMIT); halts on timeout. */
    for (poll_i = 0U;
         !DL_AESADV_isInputContextWriteable(AESADV) && poll_i < AESADV_POLL_LIMIT;
         poll_i++) {}

    if (poll_i >= AESADV_POLL_LIMIT) {
        security_halt();
    }
}

/* -----------------------------------------------------------------------
 * poll_input_ready — wait until AESADV input buffer is empty.
 * Loop counter poll_i in [0, AESADV_POLL_LIMIT); halts on timeout.
 * ---------------------------------------------------------------------- */
static void poll_input_ready(void)
{
    uint32_t poll_i;
    for (poll_i = 0U;
         !DL_AESADV_isInputReady(AESADV) && poll_i < AESADV_POLL_LIMIT;
         poll_i++) {}

    if (poll_i >= AESADV_POLL_LIMIT) {
        security_halt();
    }
}


/* -----------------------------------------------------------------------
 * poll_output_ready — wait until AESADV output block is available.
 * Loop counter poll_i in [0, AESADV_POLL_LIMIT); halts on timeout.
 * ---------------------------------------------------------------------- */
static void poll_output_ready(void)
{
    uint32_t poll_i;
    for (poll_i = 0U;
         !DL_AESADV_isOutputReady(AESADV) && poll_i < AESADV_POLL_LIMIT;
         poll_i++) {}

    if (poll_i >= AESADV_POLL_LIMIT) {
        security_halt();
    }
}


/* -----------------------------------------------------------------------
 * poll_tag_ready — wait until saved output context (TAG) is available.
 * Loop counter poll_i in [0, AESADV_POLL_LIMIT); halts on timeout.
 * ---------------------------------------------------------------------- */
static void poll_tag_ready(void)
{
    uint32_t poll_i;
    for (poll_i = 0U;
         !DL_AESADV_isSavedOutputContextReady(AESADV) &&
         poll_i < AESADV_POLL_LIMIT;
         poll_i++) {}

    if (poll_i >= AESADV_POLL_LIMIT) {
        security_halt();
    }
}


/* -----------------------------------------------------------------------
 * feed_aad_blocks — push all AAD to AESADV; no output is produced.
 *
 * AAD must be fed in 16-byte blocks; the last block is zero-padded.
 * The hardware uses the aadLength set in initGCM to know where AAD ends.
 *
 * Loop counter blk_i in [0, num_blks); terminates exactly at num_blks.
 * ---------------------------------------------------------------------- */
static void feed_aad_blocks(const uint8_t *aad, size_t aad_len)
{
    uint32_t in_block[AES_BLOCK_WORDS];
    size_t   num_blks;
    size_t   blk_i;
    size_t   byte_off;
    size_t   copy_bytes;

    if (aad_len == 0U) {
        return;
    }

    num_blks = (aad_len + AES_BLOCK_BYTES - 1U) / AES_BLOCK_BYTES;

    for (blk_i = 0U; blk_i < num_blks; blk_i++) {
        byte_off   = blk_i * AES_BLOCK_BYTES;
        copy_bytes = aad_len - byte_off;
        if (copy_bytes > AES_BLOCK_BYTES) {
            copy_bytes = AES_BLOCK_BYTES;
        }

        /* Zero-pad the block, then copy valid AAD bytes. */
        memset(in_block, 0, sizeof(in_block));
        memcpy(in_block, aad + byte_off, copy_bytes);

        poll_input_ready();
        DL_AESADV_loadInputDataAligned(AESADV, in_block);
        /* No output read for AAD blocks. */
    }

    /* Clear local copy of AAD data. */
    secure_zero(in_block, sizeof(in_block));
}


/* -----------------------------------------------------------------------
 * feed_crypto_blocks — push plaintext/ciphertext, collect output.
 *
 * Each 16-byte input block is written; the corresponding 16-byte output
 * block is read back.  The partial last block is zero-padded on input;
 * only the first (data_len % 16) bytes of the output are valid and copied.
 *
 * Loop counter blk_i in [0, num_blks); terminates exactly at num_blks.
 * ---------------------------------------------------------------------- */
static void feed_crypto_blocks(const uint8_t *input, uint8_t *output,
                                size_t data_len)
{
    uint32_t in_block[AES_BLOCK_WORDS];
    uint32_t out_block[AES_BLOCK_WORDS];
    size_t   num_blks;
    size_t   blk_i;
    size_t   byte_off;
    size_t   copy_bytes;

    if (data_len == 0U) {
        return;
    }

    num_blks = (data_len + AES_BLOCK_BYTES - 1U) / AES_BLOCK_BYTES;

    for (blk_i = 0U; blk_i < num_blks; blk_i++) {
        byte_off   = blk_i * AES_BLOCK_BYTES;
        copy_bytes = data_len - byte_off;
        if (copy_bytes > AES_BLOCK_BYTES) {
            copy_bytes = AES_BLOCK_BYTES;
        }

        /* Build zero-padded input block. */
        memset(in_block, 0, sizeof(in_block));
        memcpy(in_block, input + byte_off, copy_bytes);

        poll_input_ready();
        DL_AESADV_loadInputDataAligned(AESADV, in_block);

        poll_output_ready();
        DL_AESADV_readOutputDataAligned(AESADV, out_block);

        /* Copy only the valid output bytes (guards against partial last block). */
        memcpy(output + byte_off, out_block, copy_bytes);
    }

    secure_zero(in_block,  sizeof(in_block));
    secure_zero(out_block, sizeof(out_block));
}


/* -----------------------------------------------------------------------
 * aesadv_gcm_run — shared setup and teardown for encrypt and decrypt.
 *
 * Sets key, configures GCM mode, feeds AAD + data, reads TAG.
 * On return: out_buf holds ciphertext or plaintext; tag_out holds the
 * hardware-computed 16-byte authentication tag.
 *
 * Returns 0 on success, -1 on any setup failure (tag comparison is the
 * caller's responsibility for decryption).
 * ---------------------------------------------------------------------- */
static int aesadv_gcm_run(DL_AESADV_DIR    direction,
                          const uint8_t   *key,
                          const uint8_t   *nonce,
                          const uint8_t   *aad,      size_t aad_len,
                          const uint8_t   *in_buf,   size_t data_len,
                          uint8_t         *out_buf,
                          uint8_t         *tag_out)
{
    /* Aligned local copies — STORAGE_KEY alignment is not guaranteed. */
    uint32_t key_buf[8];                    /* AES-256: 8 × uint32_t = 32 B  */
    uint32_t iv_buf[AES_BLOCK_WORDS];       /* 128-bit IV                     */
    uint32_t tag_buf[AES_BLOCK_WORDS];      /* 128-bit TAG output             */
    uint8_t *iv_bytes = (uint8_t *)iv_buf;

    DL_AESADV_Config cfg;

    /* --- Build GCM IV = nonce || counter=1 (standard J0) --- */
    memset(iv_buf, 0, sizeof(iv_buf));
    memcpy(iv_bytes, nonce, NONCE_SIZE);    /* bytes [0..11]  */
    iv_bytes[15] = 0x01U;                  /* byte  [15]: counter = 1 big-endian;
                                              ARM loads iv[12..15] as uint32
                                              IV3 = 0x01000000 (LE), per TRM */

    /* --- Power-enable and reset; poll until reset cycle completes --- */
    aesadv_reset_and_enable();

    /* --- Disable DMA; use CPU register polling --- */
    DL_AESADV_disableDMAOperation(AESADV);

    /* --- Load 256-bit key into aligned buffer then into hardware --- */
    memcpy(key_buf, key, GCM_KEY_SIZE);
    DL_AESADV_setKeyAligned(AESADV, key_buf, DL_AESADV_KEY_SIZE_256_BIT);
    secure_zero(key_buf, sizeof(key_buf));  /* key off stack immediately */

    /* --- Configure GCM autonomous mode --- */
    memset(&cfg, 0, sizeof(cfg));
    cfg.mode              = DL_AESADV_MODE_GCM_AUTONOMOUS;
    cfg.direction         = direction;
    cfg.iv                = iv_bytes;             /* 4-byte aligned uint32_t[] */
    cfg.lowerCryptoLength = (uint32_t)data_len;
    cfg.upperCryptoLength = 0U;
    cfg.aadLength         = (uint32_t)aad_len;

    DL_AESADV_initGCM(AESADV, &cfg);

    /* --- Feed AAD (auth-only, no ciphertext produced) --- */
    feed_aad_blocks(aad, aad_len);

    /* GCM autonomous mode needs a crypto-phase trigger even when data_len
     * is zero (GMAC / AAD-only case); forceInputDataAvailable() provides
     * that kick so poll_tag_ready() does not hang. */
    if (data_len == 0U) {
        DL_AESADV_forceInputDataAvailable(AESADV);
    }

    /* --- Feed crypto data and collect output --- */
    feed_crypto_blocks(in_buf, out_buf, data_len);

    /* --- Read authentication TAG --- */
    poll_tag_ready();
    DL_AESADV_readTAGAligned(AESADV, tag_buf);
    memcpy(tag_out, tag_buf, TAG_SIZE);

    /* --- Reset peripheral to clear key from hardware registers --- */
    aesadv_reset_and_enable();

    secure_zero(iv_buf,  sizeof(iv_buf));
    secure_zero(tag_buf, sizeof(tag_buf));

    return 0;
}


/* -----------------------------------------------------------------------
 * crypto_init — power-enable AESADV; wolfcrypt needs no init.
 * ---------------------------------------------------------------------- */
int crypto_init(void)
{
    aesadv_reset_and_enable();
    return 0;
}


/* -----------------------------------------------------------------------
 * generate_nonce — fill nonce_out with NONCE_SIZE TRNG bytes.
 * Loop counter i in [0, NONCE_SIZE); terminates at NONCE_SIZE exactly.
 * ---------------------------------------------------------------------- */
int generate_nonce(uint8_t *nonce_out)
{
    uint8_t i;

    if (nonce_out == NULL) { return -1; }

    for (i = 0U; i < NONCE_SIZE; i++) {
        nonce_out[i] = trng_read_byte();
    }
    return 0;
}


/* -----------------------------------------------------------------------
 * aes_gcm_encrypt — AES-256-GCM encryption via AESADV hardware.
 *
 * SCA: random_delay() before key load slides the key-schedule power
 * signature across a ~20 ms trace window.
 * ---------------------------------------------------------------------- */
int aes_gcm_encrypt(const uint8_t *key,
                    const uint8_t *nonce,
                    const uint8_t *aad,        size_t aad_len,
                    const uint8_t *plaintext,  size_t pt_len,
                    uint8_t       *ciphertext,
                    uint8_t       *tag)
{
    if (key == NULL || nonce == NULL || ciphertext == NULL || tag == NULL) {
        return -1;
    }
    if (aad_len > MAX_AAD_SIZE || pt_len > MAX_PLAINTEXT_SIZE) {
        return -1;
    }

    random_delay();   /* SCA jitter before key enters hardware */

    return aesadv_gcm_run(DL_AESADV_DIR_ENCRYPT,
                          key, nonce,
                          aad, aad_len,
                          plaintext, pt_len,
                          ciphertext, tag);
}


/* -----------------------------------------------------------------------
 * aes_gcm_decrypt — AES-256-GCM decryption via AESADV hardware.
 *
 * The hardware computes a tag over the ciphertext; we compare it with the
 * expected tag using secure_compare() (constant-time, no early exit).
 * Plaintext is zeroed on any failure — no partial plaintext leaks.
 * ---------------------------------------------------------------------- */
int aes_gcm_decrypt(const uint8_t *key,
                    const uint8_t *nonce,
                    const uint8_t *aad,        size_t aad_len,
                    const uint8_t *ciphertext, size_t ct_len,
                    const uint8_t *tag,
                    uint8_t       *plaintext)
{
    uint8_t computed_tag[TAG_SIZE];
    int     ret;

    if (key == NULL || nonce == NULL || tag == NULL || plaintext == NULL) {
        return -1;
    }
    if (aad_len > MAX_AAD_SIZE || ct_len > MAX_PLAINTEXT_SIZE) {
        return -1;
    }

    random_delay();   /* SCA jitter before key enters hardware */

    ret = aesadv_gcm_run(DL_AESADV_DIR_DECRYPT,
                         key, nonce,
                         aad, aad_len,
                         ciphertext, ct_len,
                         plaintext, computed_tag);
    if (ret != 0) {
        secure_zero(plaintext,    ct_len);
        secure_zero(computed_tag, sizeof(computed_tag));
        return -1;
    }

    /* Constant-time tag comparison — must not short-circuit. */
    if (!secure_compare(computed_tag, tag, TAG_SIZE)) {
        secure_zero(plaintext,    ct_len);
        secure_zero(computed_tag, sizeof(computed_tag));
        return -1;
    }

    secure_zero(computed_tag, sizeof(computed_tag));
    return 0;
}


/* -----------------------------------------------------------------------
 * hmac_sha256 — HMAC-SHA256 with mandatory domain separator (wolfcrypt).
 *
 * Computes HMAC(key, data || domain) via two wc_HmacUpdate calls so no
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
    uint8_t pos = 0U;

    out[pos++] = slot;

    /* uuid — loop counter i in [0, 16) */
    for (i = 0U; i < 16U; i++) { out[pos++] = uuid[i]; }

    /* group_id little-endian */
    out[pos++] = (uint8_t)(group_id & 0xFFU);
    out[pos++] = (uint8_t)((group_id >> 8) & 0xFFU);

    /* name zero-padded — loop counter i in [0, 32) */
    for (i = 0U; i < 32U; i++) {
        out[pos++] = (name != NULL && name[i] != '\0') ? (uint8_t)name[i] : 0U;
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
    uint8_t pos = 0U;

    /* recv_chal — loop counter i in [0, 12) */
    for (i = 0U; i < 12U; i++) { out[pos++] = recv_chal[i]; }

    /* send_chal — loop counter i in [0, 12) */
    for (i = 0U; i < 12U; i++) { out[pos++] = send_chal[i]; }

    out[pos++] = slot;

    /* uuid — loop counter i in [0, 16) */
    for (i = 0U; i < 16U; i++) { out[pos++] = uuid[i]; }

    /* group_id little-endian */
    out[pos++] = (uint8_t)(group_id & 0xFFU);
    out[pos++] = (uint8_t)((group_id >> 8) & 0xFFU);

    /* name zero-padded — loop counter i in [0, 32) */
    for (i = 0U; i < 32U; i++) {
        out[pos++] = (name != NULL && name[i] != '\0') ? (uint8_t)name[i] : 0U;
    }

    return TRANSFER_AAD_SIZE;  /* 75 */
}
