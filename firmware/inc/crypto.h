/**
 * @file crypto.h
 * @brief Cryptographic API for eCTF HSM
 * @date 2026
 * @copyright Copyright (c) 2026 The MITRE Corporation
 *
 * Two-key architecture:
 * - GCM_KEY (KEYSTORE slot 0): AES-256-GCM encryption + integrity
 * - AUTH_KEY (flash/RAM): HMAC-SHA256 authentication
 *
 * Key storage rationale:
 * - GCM_KEY in hardware KEYSTORE: Write-only, feeds directly to AESADV
 * - AUTH_KEY in flash: wolfcrypt HMAC requires key accessible in memory
 *
 * Security features:
 * - Hardware AES-GCM with constant-time tag verification
 * - Double-computation for glitch/fault resistance
 * - Random delays between operations
 */

#ifndef __CRYPTO_H__
#define __CRYPTO_H__

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/*
 * Cryptographic Constants
 */
#define GCM_KEY_SIZE    32      /* 256-bit AES-GCM key */
#define AUTH_KEY_SIZE   32      /* 256-bit HMAC key */
#define NONCE_SIZE      12      /* 96-bit GCM nonce */
#define TAG_SIZE        16      /* 128-bit GCM authentication tag */
#define HMAC_SIZE       32      /* 256-bit HMAC-SHA256 output */
#define AES_BLOCK_SIZE  16      /* AES block size */

/* KEYSTORE slot for GCM key */
#define KEYSTORE_SLOT_GCM   0

/* Maximum sizes */
#define MAX_AAD_SIZE        64      /* Max additional authenticated data */
#define MAX_PLAINTEXT_SIZE  8192    /* Max file contents */

/*
 * Error Codes
 */
#define CRYPTO_OK            0
#define CRYPTO_ERR_PARAM    -1      /* Invalid parameter (NULL, etc.) */
#define CRYPTO_ERR_LENGTH   -2      /* Invalid length */
#define CRYPTO_ERR_TAG      -3      /* GCM tag verification failed */
#define CRYPTO_ERR_ALIGN    -4      /* Buffer not 32-bit aligned */
#define CRYPTO_ERR_HARDWARE -5      /* Hardware peripheral error */
#define CRYPTO_ERR_DFA      -6      /* DFA/glitch check failed (system halts) */
#define CRYPTO_ERR_HMAC     -7      /* HMAC computation failed */

/*
 * HMAC Domain Separators
 *
 * Used to prevent cross-protocol attacks.
 * Appended to data before HMAC computation.
 */
#define HMAC_DOMAIN_SENDER          "sender"
#define HMAC_DOMAIN_RECEIVER        "receiver"
#define HMAC_DOMAIN_INTERROGATE_REQ "interrogate_req"
#define HMAC_DOMAIN_INTERROGATE_RSP "interrogate_resp"

/*
 * Initialization
 */

/**
 * @brief Initialize crypto subsystem.
 *
 * Loads GCM_KEY into hardware KEYSTORE slot 0.
 * Must be called once at boot after TRNG initialization.
 *
 * @return CRYPTO_OK on success, negative error code on failure
 */
int crypto_init(void);

/*
 * AES-256-GCM Functions (Hardware AESADV + KEYSTORE)
 *
 * Uses GCM_KEY from KEYSTORE slot 0.
 * Tag verification performed in hardware (constant-time).
 * Double-computation for glitch resistance.
 */

/**
 * @brief Encrypt and authenticate data using AES-256-GCM.
 *
 * @param nonce 12-byte nonce (must be unique per encryption)
 * @param aad Additional authenticated data (not encrypted, but authenticated)
 * @param aad_len Length of AAD
 * @param plaintext Data to encrypt
 * @param pt_len Length of plaintext
 * @param ciphertext Output buffer for encrypted data (same size as plaintext)
 * @param tag Output buffer for 16-byte authentication tag
 * @return CRYPTO_OK on success, negative error code on failure
 *
 * @note Halts on glitch detection (mismatched computations)
 */
int aes_gcm_encrypt(const uint8_t *nonce,
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *plaintext, size_t pt_len,
                    uint8_t *ciphertext,
                    uint8_t *tag);

/**
 * @brief Decrypt and verify data using AES-256-GCM.
 *
 * @param nonce 12-byte nonce (same as used for encryption)
 * @param aad Additional authenticated data
 * @param aad_len Length of AAD
 * @param ciphertext Encrypted data
 * @param ct_len Length of ciphertext
 * @param tag 16-byte authentication tag to verify
 * @param plaintext Output buffer for decrypted data
 * @return CRYPTO_OK on success, CRYPTO_ERR_TAG if tag verification fails
 *
 * @note Tag verification is performed in hardware (constant-time)
 * @note On tag failure, plaintext buffer is zeroed
 */
int aes_gcm_decrypt(const uint8_t *nonce,
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *ciphertext, size_t ct_len,
                    const uint8_t *tag,
                    uint8_t *plaintext);

/*
 * HMAC-SHA256 Functions (wolfcrypt software)
 *
 * Uses AUTH_KEY from secrets.h.
 * Required for challenge-response authentication.
 */

/**
 * @brief Compute HMAC-SHA256.
 *
 * @param key 32-byte HMAC key
 * @param data Data to authenticate
 * @param data_len Length of data
 * @param output 32-byte output buffer for HMAC
 * @return CRYPTO_OK on success, CRYPTO_ERR_HMAC on failure
 */
int hmac_sha256(const uint8_t *key,
                const uint8_t *data, size_t data_len,
                uint8_t *output);

/**
 * @brief Compute HMAC-SHA256 with domain separator.
 *
 * Computes HMAC(key, data || domain_separator).
 * Prevents cross-protocol attacks.
 *
 * @param key 32-byte HMAC key
 * @param data Data to authenticate
 * @param data_len Length of data
 * @param domain Domain separator string (e.g., "sender", "receiver")
 * @param output 32-byte output buffer for HMAC
 * @return CRYPTO_OK on success, CRYPTO_ERR_HMAC on failure
 */
int hmac_sha256_domain(const uint8_t *key,
                       const uint8_t *data, size_t data_len,
                       const char *domain,
                       uint8_t *output);

/**
 * @brief Verify HMAC-SHA256 in constant time.
 *
 * @param key 32-byte HMAC key
 * @param data Data that was authenticated
 * @param data_len Length of data
 * @param expected_mac Expected 32-byte HMAC value
 * @return true if MAC matches, false otherwise
 */
bool hmac_verify(const uint8_t *key,
                 const uint8_t *data, size_t data_len,
                 const uint8_t *expected_mac);

/**
 * @brief Verify HMAC-SHA256 with domain separator in constant time.
 *
 * @param key 32-byte HMAC key
 * @param data Data that was authenticated
 * @param data_len Length of data
 * @param domain Domain separator string
 * @param expected_mac Expected 32-byte HMAC value
 * @return true if MAC matches, false otherwise
 */
bool hmac_verify_domain(const uint8_t *key,
                        const uint8_t *data, size_t data_len,
                        const char *domain,
                        const uint8_t *expected_mac);

/*
 * Nonce Generation
 */

/**
 * @brief Generate a random 12-byte nonce for GCM.
 *
 * Uses hardware TRNG.
 *
 * @param nonce Output buffer (12 bytes)
 * @return CRYPTO_OK on success, negative error code on failure
 */
int generate_nonce(uint8_t *nonce);

/*
 * AAD Construction Helpers
 */

/**
 * @brief Build AAD for file storage.
 *
 * Format: slot(1) || uuid(16) || group_id(2) || name(32)
 * Total: 51 bytes
 *
 * @param slot File slot index
 * @param uuid 16-byte unique file ID
 * @param group_id Permission group (little-endian)
 * @param name 32-byte null-padded filename
 * @param aad Output buffer (at least 51 bytes)
 * @return Length of AAD (51)
 */
size_t build_storage_aad(uint8_t slot,
                         const uint8_t *uuid,
                         uint16_t group_id,
                         const char *name,
                         uint8_t *aad);

/**
 * @brief Build AAD for file transfer.
 *
 * Format: receiver_challenge(12) || sender_challenge(12) || slot(1) || uuid(16) || group_id(2)
 * Total: 43 bytes
 *
 * @param receiver_challenge 12-byte receiver challenge
 * @param sender_challenge 12-byte sender challenge
 * @param slot Requested file slot
 * @param uuid 16-byte file UUID
 * @param group_id File's permission group
 * @param aad Output buffer (at least 43 bytes)
 * @return Length of AAD (43)
 */
size_t build_transfer_aad(const uint8_t *receiver_challenge,
                          const uint8_t *sender_challenge,
                          uint8_t slot,
                          const uint8_t *uuid,
                          uint16_t group_id,
                          uint8_t *aad);

/*
 * Alignment Helpers
 */

/**
 * @brief Check if pointer is 4-byte aligned.
 */
static inline bool is_aligned(const void *ptr)
{
    return ((uintptr_t)ptr & 0x3) == 0;
}

/**
 * @brief Alignment attribute for buffer declarations.
 */
#define ALIGNED_BUFFER __attribute__((aligned(4)))

#endif /* __CRYPTO_H__ */
