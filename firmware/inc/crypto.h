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

/*
 * Constants
 */
#define GCM_KEY_SIZE    32
#define AUTH_KEY_SIZE   32
#define NONCE_SIZE      12
#define TAG_SIZE        16
#define HMAC_SIZE       32
#define AES_BLOCK_SIZE  16
#define MAX_AAD_SIZE        64
#define MAX_PLAINTEXT_SIZE  8192

/*
 * HMAC Domain Separators — every HMAC call requires one
 */
#define HMAC_DOMAIN_SENDER          "sender"
#define HMAC_DOMAIN_RECEIVER        "receiver"
#define HMAC_DOMAIN_INTERROGATE_REQ "interrogate_req"
#define HMAC_DOMAIN_INTERROGATE_RSP "interrogate_resp"
#define HMAC_DOMAIN_PERMISSION      "permission"

/**
 * @brief Initialize crypto subsystem (no-op, retained for API compatibility).
 */
int crypto_init(void);

/**
 * @brief AES-256-GCM encrypt. Key loaded from flash per call.
 */
int aes_gcm_encrypt(const uint8_t *nonce,
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *plaintext, size_t pt_len,
                    uint8_t *ciphertext,
                    uint8_t *tag);

/**
 * @brief AES-256-GCM decrypt. Plaintext zeroed on any failure.
 */
int aes_gcm_decrypt(const uint8_t *nonce,
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *ciphertext, size_t ct_len,
                    const uint8_t *tag,
                    uint8_t *plaintext);

/**
 * @brief HMAC-SHA256 with mandatory domain separator.
 *        Computes HMAC(key, data || domain).
 */
int hmac_sha256(const uint8_t *key,
                const uint8_t *data, size_t data_len,
                const char *domain,
                uint8_t *output);

/**
 * @brief Verify HMAC-SHA256 (constant-time, glitch-resistant).
 *        Double-compute with random delay; halts on mismatch.
 */
bool hmac_verify(const uint8_t *key,
                 const uint8_t *data, size_t data_len,
                 const char *domain,
                 const uint8_t *expected_mac);

/**
 * @brief Generate 12-byte random nonce from hardware TRNG.
 */
int generate_nonce(uint8_t *nonce);

/**
 * @brief Build AAD for file storage.
 *        Format: slot(1) || uuid(16) || group_id(2) || name(32) = 51 bytes.
 */
size_t build_storage_aad(uint8_t slot,
                         const uint8_t *uuid,
                         uint16_t group_id,
                         const char *name,
                         uint8_t *aad);

/**
 * @brief Build AAD for file transfer.
 *        Format: recv_chal(12) || send_chal(12) || slot(1) || uuid(16) || group_id(2) = 43 bytes.
 */
size_t build_transfer_aad(const uint8_t *receiver_challenge,
                          const uint8_t *sender_challenge,
                          uint8_t slot,
                          const uint8_t *uuid,
                          uint16_t group_id,
                          uint8_t *aad);

#endif /* __CRYPTO_H__ */
