/**
 * @file security.h
 * @brief Security primitives header for eCTF HSM
 * @date 2026
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#ifndef __SECURITY_H__
#define __SECURITY_H__

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

/*
 * Constants
 */
#define MAX_PERMS 8
#define PIN_LENGTH 6

/*
 * Permission types - uppercase to match protocol
 */
typedef enum {
    PERM_READ = 'R',
    PERM_WRITE = 'W',
    PERM_RECEIVE = 'C',
} permission_enum_t;

/*
 * Permission structure
 */
typedef struct {
    uint16_t group_id;
    bool read;
    bool write;
    bool receive;
} group_permission_t;

/*
 * TRNG Functions
 */

/**
 * @brief Initialize the hardware TRNG
 * @return 0 on success, -1 on failure
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

/**
 * @brief Fill a buffer with random bytes
 * @param buf Buffer to fill
 * @param len Number of bytes to fill
 * @return 0 on success, -1 on failure
 */
int trng_fill_buffer(uint8_t *buf, size_t len);

/*
 * Core Security Functions
 */

/**
 * @brief Validate a pin against the HSM's pin
 *
 * @param pin Requested pin to validate.
 *
 * @return True if the pin is valid. False if not.
 */
bool check_pin(unsigned char *pin);

/**
 * @brief Ensure the HSM has the requested permission
 *
 * @param group_id Group ID.
 * @param perm Permission type.
 *
 * @return True if the HSM has the correct permission. False if not.
 */
bool validate_permission(uint16_t group_id, permission_enum_t perm);

/**
 * @brief Constant-time memory comparison
 * @param a First buffer
 * @param b Second buffer
 * @param len Length to compare
 * @return true if buffers are equal, false otherwise
 */
bool secure_compare(const void *a, const void *b, size_t len);

/*
 * Input Validation Functions
 */

/**
 * @brief Validate file slot number
 * @param slot Slot number to validate
 * @return true if slot is valid (0 to MAX_FILE_COUNT-1)
 */
bool validate_slot(uint8_t slot);

/**
 * @brief Validate filename string
 * @param name Filename to validate
 * @param max_len Maximum allowed length
 * @return true if name is valid (printable ASCII, null-terminated)
 */
bool validate_name(const char *name, size_t max_len);

/**
 * @brief Validate permission count
 * @param count Permission count to validate
 * @return true if count is valid (0 to MAX_PERMS)
 */
bool validate_perm_count(uint8_t count);

/**
 * @brief Validate contents length
 * @param len Length to validate
 * @return true if length is valid (0 to MAX_CONTENTS_SIZE)
 */
bool validate_contents_len(uint16_t len);

/**
 * @brief Validate boolean value
 * @param value Value to validate
 * @return true if value is 0 or 1
 */
bool validate_bool(uint8_t value);

/*
 * Memory Safety Functions
 */

/**
 * @brief Secure memory clear (won't be optimized away)
 * @param ptr Pointer to memory to clear
 * @param len Number of bytes to clear
 */
void explicit_bzero(void *ptr, size_t len);

/**
 * @brief Busy-wait delay in milliseconds
 * @param ms Milliseconds to wait
 * @note Uses CYCLES_PER_MS for timing - calibrate for your hardware
 */
void busy_wait_ms(uint32_t ms);

#endif  /* __SECURITY_H__ */
