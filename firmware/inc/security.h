/**
 * @file security.h
 * @brief Security primitives for eCTF HSM
 * @date 2026
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#ifndef __SECURITY_H__
#define __SECURITY_H__

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#define MAX_PERMS 8
#define PIN_LENGTH 6

/* Default cycles per millisecond at 32MHz */
#ifndef CYCLES_PER_MS
#define CYCLES_PER_MS 32000
#endif

typedef enum {
    PERM_READ = 'R',
    PERM_WRITE = 'W',
    PERM_RECEIVE = 'C',
} permission_enum_t;

typedef struct {
    uint16_t group_id;
    bool read;
    bool write;
    bool receive;
} group_permission_t;

/* TRNG Functions */

/**
 * @brief Initialize hardware TRNG
 * @return 0 on success, negative error code on failure
 */
int trng_init(void);

/**
 * @brief Read a 32-bit random word from TRNG
 * @return Random 32-bit value
 */
uint32_t trng_read_word(void);

/**
 * @brief Read a single random byte from TRNG
 * @return Random 8-bit value
 */
uint8_t trng_read_byte(void);

/* Timing Functions */

/**
 * @brief Precise cycle-accurate delay using assembly
 * @param cycles Number of CPU cycles to delay
 * 
 * Based on TI SDK dl_common.c implementation.
 * At 32MHz: 32000 cycles ≈ 1ms
 */
void delay_cycles(uint32_t cycles);

/**
 * @brief Delay in milliseconds
 * @param ms Milliseconds to wait
 */
void delay_ms(uint32_t ms);

/**
 * @brief Random delay for glitch resistance
 * 
 * Delays a random number of cycles (0 to ~4ms) using TRNG.
 * Used between security-critical operations to prevent timing and glitch attacks.
 */
void random_delay(void);

/* Authentication Functions */

/**
 * @brief Validate PIN against stored HSM PIN
 * @param pin 6-byte PIN to validate
 * @return true if valid, false otherwise (with 5s delay on failure)
 */
bool check_pin(unsigned char *pin);

/**
 * @brief Check if HSM has permission for group
 * @param group_id Group ID to check
 * @param perm Permission type (PERM_READ, PERM_WRITE, PERM_RECEIVE)
 * @return true if permission granted
 */
bool validate_permission(uint16_t group_id, permission_enum_t perm);

/**
 * @brief Constant-time memory comparison
 * @param a First buffer
 * @param b Second buffer
 * @param len Bytes to compare
 * @return true if equal
 */
bool secure_compare(const void *a, const void *b, size_t len);

/* Input Validation Functions */

/**
 * @brief Validate file slot number (0 to MAX_FILE_COUNT-1)
 */
bool validate_slot(uint8_t slot);

/**
 * @brief Validate filename (printable ASCII, null-terminated)
 */
bool validate_name(const char *name, size_t max_len);

/**
 * @brief Validate permission count (0 to MAX_PERMS)
 */
bool validate_perm_count(uint8_t count);

/**
 * @brief Validate file contents length (0 to MAX_CONTENTS_SIZE)
 */
bool validate_contents_len(uint16_t len);

/**
 * @brief Validate boolean value (0 or 1)
 */
bool validate_bool(uint8_t value);

#endif /* __SECURITY_H__ */
