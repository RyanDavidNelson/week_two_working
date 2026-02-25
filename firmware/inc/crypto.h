/**
 * @file crypto.h
 * @brief Cryptographic API for eCTF HSM
 * @date 2026
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#ifndef __CRYPTO_H__
#define __CRYPTO_H__

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* ------------------------------------------------------------------ */
/* Size constants                                                       */
/* ------------------------------------------------------------------ */
#define GCM_KEY_SIZE        32   /* AES-256 key length               */
#define AUTH_KEY_SIZE       32   /* HMAC-SHA256 key length            */
#define NONCE_SIZE          12   /* GCM nonce length                  */
#define TAG_SIZE            16   /* GCM authentication tag length     */
#define HMAC_SIZE           32   /* HMAC-SHA256 output length         */

/* AAD layouts (bytes):
 *   Storage : slot(1) || uuid(16) || group_id(2 LE) || name(32) = 51
 *   Transfer: recv_chal(12) || send_chal(12) || slot(1) || uuid(16)
 *             || group_id(2 LE) || name(32)                      = 75
 */
#define STORAGE_AAD_SIZE    51
#define TRANSFER_AAD_SIZE   75
#define MAX_AAD_SIZE        80   /* >= TRANSFER_AAD_SIZE; upper-bound guard */
#define MAX_PLAINTEXT_SIZE  8192

/* ------------------------------------------------------------------ */
/* HMAC domain separators — every HMAC call requires one.              */
/* Prevents cross-context MAC collisions.                              */
/* ------------------------------------------------------------------ */
#define HMAC_DOMAIN_PIN              "pin"
#define HMAC_DOMAIN_PERMISSION       "permission"
#define HMAC_DOMAIN_SENDER           "sender"
#define HMAC_DOMAIN_RECEIVER         "receiver"
#define HMAC_DOMAIN_INTERROGATE_REQ  "interrogate_req"
#define HMAC_DOMAIN_INTERROGATE_RSP  "interrogate_resp"

/* ------------------------------------------------------------------ */
/* Crypto initialisation                                               */
/* ------------------------------------------------------------------ */

/** @brief No-op; retained for API compatibility. */
int crypto_init(void);

/* ------------------------------------------------------------------ */
/* AES-256-GCM (wolfcrypt software, WC_AES_BITSLICED build flag)      */
/* ------------------------------------------------------------------ */

/**
 * @brief AES-256-GCM encrypt.
 *
 * @param key        32-byte AES key (STORAGE_KEY or TRANSFER_KEY).
 * @param nonce      12-byte TRNG-generated nonce.
 * @param aad        Additional authenticated data (NULL if aad_len == 0).
 * @param aad_len    Byte length of AAD; must be <= MAX_AAD_SIZE.
 * @param plaintext  Input plaintext (NULL if pt_len == 0).
 * @param pt_len     Plaintext length; must be <= MAX_PLAINTEXT_SIZE.
 * @param ciphertext Output ciphertext buffer (same length as plaintext).
 * @param tag        Output 16-byte GCM authentication tag.
 * @return 0 on success, -1 on error.
 */
int aes_gcm_encrypt(const uint8_t *key,
                    const uint8_t *nonce,
                    const uint8_t *aad,        size_t aad_len,
                    const uint8_t *plaintext,  size_t pt_len,
                    uint8_t       *ciphertext,
                    uint8_t       *tag);

/**
 * @brief AES-256-GCM decrypt.  Plaintext is zeroed on any failure.
 *
 * @param key        32-byte AES key (STORAGE_KEY or TRANSFER_KEY).
 * @param nonce      12-byte nonce (must match the encrypt-time nonce).
 * @param aad        Additional authenticated data (NULL if aad_len == 0).
 * @param aad_len    Byte length of AAD; must be <= MAX_AAD_SIZE.
 * @param ciphertext Input ciphertext.
 * @param ct_len     Ciphertext length; must be <= MAX_PLAINTEXT_SIZE.
 * @param tag        16-byte GCM authentication tag to verify.
 * @param plaintext  Output plaintext buffer (same length as ciphertext).
 * @return 0 on success, -1 on tag failure or any error.
 */
int aes_gcm_decrypt(const uint8_t *key,
                    const uint8_t *nonce,
                    const uint8_t *aad,        size_t aad_len,
                    const uint8_t *ciphertext, size_t ct_len,
                    const uint8_t *tag,
                    uint8_t       *plaintext);

/* ------------------------------------------------------------------ */
/* HMAC-SHA256 (wolfcrypt software)                                    */
/* ------------------------------------------------------------------ */

/**
 * @brief HMAC-SHA256 with mandatory domain separator.
 *        Computes HMAC(key, data || domain).
 *
 * @param key       32-byte HMAC key.
 * @param data      Input data (NULL if data_len == 0).
 * @param data_len  Byte length of data.
 * @param domain    Null-terminated domain separator string.
 * @param output    32-byte output buffer.
 * @return 0 on success, -1 on any wolfcrypt error.
 */
int hmac_sha256(const uint8_t *key,
                const uint8_t *data, size_t data_len,
                const char    *domain,
                uint8_t       *output);

/**
 * @brief Verify HMAC-SHA256 — constant-time and glitch-resistant.
 *
 * Computes the MAC twice with a random_delay() between passes.
 * Calls security_halt() if both passes disagree (fault injection).
 * Uses secure_compare() for the final comparison — no early exit.
 *
 * @param key      32-byte HMAC key.
 * @param data     Input data.
 * @param data_len Byte length of data.
 * @param domain   Null-terminated domain separator string.
 * @param expected 32-byte expected MAC.
 * @return true if MAC matches, false otherwise.
 */
bool hmac_verify(const uint8_t *key,
                 const uint8_t *data, size_t data_len,
                 const char    *domain,
                 const uint8_t *expected);

/* ------------------------------------------------------------------ */
/* Nonce generation                                                    */
/* ------------------------------------------------------------------ */

/**
 * @brief Fill nonce_out with NONCE_SIZE bytes from hardware TRNG.
 * @return 0 on success, -1 if nonce_out is NULL.
 */
int generate_nonce(uint8_t *nonce_out);

/* ------------------------------------------------------------------ */
/* AAD construction helpers                                            */
/* ------------------------------------------------------------------ */

/**
 * @brief Build AAD for at-rest storage encryption.
 *        Format: slot(1) || uuid(16) || group_id(2 LE) || name(32) = 51 B.
 * @return STORAGE_AAD_SIZE (51).
 */
size_t build_storage_aad(uint8_t        slot,
                         const uint8_t *uuid,
                         uint16_t       group_id,
                         const char    *name,
                         uint8_t       *out);

/**
 * @brief Build AAD for in-transit encryption.
 *        Format: recv_chal(12) || send_chal(12) || slot(1) || uuid(16)
 *                || group_id(2 LE) || name(32) = 75 B.
 * @return TRANSFER_AAD_SIZE (75).
 */
size_t build_transfer_aad(const uint8_t *recv_chal,
                          const uint8_t *send_chal,
                          uint8_t        slot,
                          const uint8_t *uuid,
                          uint16_t       group_id,
                          const char    *name,
                          uint8_t       *out);

#endif  /* __CRYPTO_H__ */
