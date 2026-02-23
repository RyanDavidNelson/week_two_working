/**
 * @file crypto.h
 * @brief Cryptographic API for eCTF HSM
 * @date 2026
 *
 * FIX C (P5): build_transfer_aad() now accepts a name parameter and
 *   appends a zero-padded 32-byte name field to the transfer AAD.
 *   New transfer AAD layout:
 *     recv_chal(12) || send_chal(12) || slot(1) || uuid(16) ||
 *     group_id(2 LE) || name(32 zero-padded) = 75 bytes.
 *   This binds the filename to the GCM tag for the transfer ciphertext,
 *   preventing a MITM on UART1 from renaming a file in flight without
 *   breaking authentication.
 *   TRANSFER_AAD_SIZE and MAX_AAD_SIZE updated accordingly.
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#ifndef __CRYPTO_H__
#define __CRYPTO_H__

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/*
 * Size constants
 */
#define GCM_KEY_SIZE    32
#define AUTH_KEY_SIZE   32
#define NONCE_SIZE      12
#define TAG_SIZE        16
#define HMAC_SIZE       32
#define AES_BLOCK_SIZE  16

/* Storage AAD: slot(1)+uuid(16)+group_id(2)+name(32) = 51 bytes */
#define STORAGE_AAD_SIZE    51
/* Transfer AAD: recv_chal(12)+send_chal(12)+slot(1)+uuid(16)+group_id(2)+name(32) = 75 bytes */
#define TRANSFER_AAD_SIZE   75
/* Headroom for both AAD variants. */
#define MAX_AAD_SIZE        80

#define MAX_PLAINTEXT_SIZE  8192

/*
 * HMAC Domain Separators — every HMAC call requires one.
 * Adding a new domain? Add it here; never call hmac_sha256 without one.
 */
#define HMAC_DOMAIN_SENDER          "sender"
#define HMAC_DOMAIN_RECEIVER        "receiver"
#define HMAC_DOMAIN_INTERROGATE_REQ "interrogate_req"
#define HMAC_DOMAIN_INTERROGATE_RSP "interrogate_resp"
#define HMAC_DOMAIN_PERMISSION      "permission"
#define HMAC_DOMAIN_PIN             "pin"   /* FIX B: HMAC-based PIN compare */

/**
 * @brief Initialize crypto subsystem (no-op, retained for API compatibility).
 */
int crypto_init(void);

/**
 * @brief AES-256-GCM encrypt.  Key loaded from flash per call.
 *
 * @param nonce       12-byte IV (from TRNG).
 * @param aad         Additional authenticated data (not encrypted).
 * @param aad_len     Length of AAD.
 * @param plaintext   Input plaintext.
 * @param pt_len      Length of plaintext.
 * @param ciphertext  Output ciphertext (same length as plaintext).
 * @param tag         Output 16-byte authentication tag.
 * @return 0 on success, -1 on error.
 */
int aes_gcm_encrypt(const uint8_t *nonce,
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *plaintext, size_t pt_len,
                    uint8_t *ciphertext,
                    uint8_t *tag);

/**
 * @brief AES-256-GCM decrypt.  Plaintext zeroed on tag failure or any error.
 *
 * @param nonce       12-byte IV stored with the file.
 * @param aad         Additional authenticated data.
 * @param aad_len     Length of AAD.
 * @param ciphertext  Input ciphertext.
 * @param ct_len      Length of ciphertext.
 * @param tag         16-byte expected authentication tag.
 * @param plaintext   Output plaintext buffer (zeroed on failure).
 * @return 0 on success, -1 on failure (tag mismatch or error).
 */
int aes_gcm_decrypt(const uint8_t *nonce,
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *ciphertext, size_t ct_len,
                    const uint8_t *tag,
                    uint8_t *plaintext);

/**
 * @brief HMAC-SHA256 with mandatory domain separator.
 *        Computes HMAC(key, data || domain).
 *
 * @param key        32-byte HMAC key.
 * @param data       Input data.
 * @param data_len   Length of data.
 * @param domain     Null-terminated domain separator string.
 * @param output     32-byte output buffer.
 * @return 0 on success, -1 on error.
 */
int hmac_sha256(const uint8_t *key,
                const uint8_t *data, size_t data_len,
                const char *domain,
                uint8_t *output);

/**
 * @brief Verify HMAC-SHA256 (constant-time, glitch-resistant).
 *        Computes twice with random_delay between; halts on mismatch.
 *
 * @param key          32-byte HMAC key.
 * @param data         Input data.
 * @param data_len     Length of data.
 * @param domain       Domain separator.
 * @param expected_mac 32-byte expected MAC.
 * @return true if MAC is valid.
 */
bool hmac_verify(const uint8_t *key,
                 const uint8_t *data, size_t data_len,
                 const char *domain,
                 const uint8_t *expected_mac);

/**
 * @brief Generate 12-byte random nonce from hardware TRNG.
 *
 * @param nonce  Output buffer (must be at least NONCE_SIZE bytes).
 * @return 0 on success, -1 on error.
 */
int generate_nonce(uint8_t *nonce);

/**
 * @brief Build AAD for file storage (STORAGE_AAD_SIZE = 51 bytes).
 *        Format: slot(1) || uuid(16) || group_id(2 LE) || name(32 zero-padded).
 *
 * @param slot      Slot index.
 * @param uuid      16-byte file UUID.
 * @param group_id  Permission group ID.
 * @param name      Null-terminated filename.
 * @param aad       Output buffer (at least STORAGE_AAD_SIZE bytes).
 * @return Bytes written (51).
 */
size_t build_storage_aad(uint8_t slot,
                         const uint8_t *uuid,
                         uint16_t group_id,
                         const char *name,
                         uint8_t *aad);

/**
 * @brief Build AAD for file transfer (TRANSFER_AAD_SIZE = 75 bytes).  (FIX C)
 *        Format: recv_chal(12) || send_chal(12) || slot(1) || uuid(16) ||
 *                group_id(2 LE) || name(32 zero-padded).
 *
 *  The name field was added (FIX C) to bind the filename to the GCM tag,
 *  preventing in-flight renaming by a MITM on the transfer interface.
 *
 * @param receiver_challenge  12-byte challenge from receiver.
 * @param sender_challenge    12-byte challenge from sender.
 * @param slot                Requested slot index.
 * @param uuid                16-byte file UUID.
 * @param group_id            Permission group ID.
 * @param name                Null-terminated filename (may be NULL).
 * @param aad                 Output buffer (at least TRANSFER_AAD_SIZE bytes).
 * @return Bytes written (75).
 */
size_t build_transfer_aad(const uint8_t *receiver_challenge,
                          const uint8_t *sender_challenge,
                          uint8_t slot,
                          const uint8_t *uuid,
                          uint16_t group_id,
                          const char *name,
                          uint8_t *aad);

#endif /* __CRYPTO_H__ */
