/**
 * @file security.h
 * @brief Security primitives for eCTF HSM
 * @date 2026
 *
 *  FIX A (P1/P2) — SECURE_PIN_CHECK / SECURE_BOOL_CHECK macros.
 *    Every security-critical boolean branch is evaluated twice with a
 *    random_delay() between passes.  Disagreement → security_halt().
 *    Turns a single-glitch bypass into a required double-glitch.
 *
 *  FIX B (P3/P6) — HMAC-based PIN verification.
 *    check_pin_cmp() computes HMAC(PIN_KEY, input_pin || "pin") and
 *    compares with PIN_HMAC.  Raw PIN never stored in .rodata.
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */
#ifndef __SECURITY_H__
#define __SECURITY_H__

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#define MAX_PERMS      8
#define PIN_LENGTH     6
#define CYCLES_PER_MS  32000

typedef enum {
    PERM_READ    = 'R',
    PERM_WRITE   = 'W',
    PERM_RECEIVE = 'C',
} permission_enum_t;

typedef struct {
    uint16_t group_id;
    bool read;
    bool write;
    bool receive;
} group_permission_t;

/**
 * @defgroup SecureBranchMacros  Double-evaluation glitch-hardened branch macros
 *
 * Callers declare ok1 and ok2 as `volatile bool`.
 * @{
 */

/**
 * SECURE_PIN_CHECK — double-evaluate check_pin_cmp(), halt on mismatch.
 * pin_ptr must remain valid for both evaluations.
 * Caller is responsible for zeroing pin_ptr and applying the 5-second
 * penalty on failure after this macro.
 */
#define SECURE_PIN_CHECK(ok1, ok2, pin_ptr)        \
    do {                                            \
        (ok1) = check_pin_cmp(pin_ptr);            \
        random_delay();                             \
        (ok2) = check_pin_cmp(pin_ptr);            \
        if ((bool)(ok1) != (bool)(ok2)) {          \
            security_halt();                        \
        }                                           \
    } while (0)

/**
 * SECURE_BOOL_CHECK — double-evaluate any boolean expression, halt on mismatch.
 * expr must be side-effect-free (evaluated twice).
 */
#define SECURE_BOOL_CHECK(ok1, ok2, expr)          \
    do {                                            \
        (ok1) = (expr);                            \
        random_delay();                             \
        (ok2) = (expr);                            \
        if ((bool)(ok1) != (bool)(ok2)) {          \
            security_halt();                        \
        }                                           \
    } while (0)

/** @} */

/*
 * Timing Functions
 */

void     delay_cycles(uint32_t cycles);
void     delay_ms(uint32_t ms);
void     random_delay(void);

/*
 * Memory Functions
 */

void     secure_zero(void *ptr, size_t len);
void     security_halt(void) __attribute__((noreturn));

/*
 * Hardware TRNG Functions
 */

int      trng_init(void);
uint32_t trng_read_word(void);
uint8_t  trng_read_byte(void);

/*
 * Authentication Functions
 */

/** Constant-time byte-wise comparison (no early exit). */
bool secure_compare(const void *a, const void *b, size_t len);

/**
 * @brief Compare pin to PIN_HMAC using HMAC(PIN_KEY, pin || "pin").
 *        No 5-second penalty.  Use SECURE_PIN_CHECK macro at call sites.
 *
 * @param pin  PIN_LENGTH-byte input PIN (hex ASCII).
 * @return true if pin matches, false otherwise.
 */
bool check_pin_cmp(const unsigned char *pin);

/**
 * @brief Full PIN check: HMAC comparison + 5-second penalty on failure.
 *        Internally calls check_pin_cmp() twice with random_delay between;
 *        halts if passes disagree.
 *
 * @param pin  PIN_LENGTH-byte input PIN.
 * @return true if correct, false (after 5s delay) if wrong.
 */
bool check_pin(unsigned char *pin);

/**
 * @brief Verify that global_permissions[] contains the requested permission.
 *        Double-pass with random_delay between; halts on mismatch.
 *
 * @param group_id  Permission group to query.
 * @param perm      Permission type (PERM_READ, PERM_WRITE, PERM_RECEIVE).
 * @return true if permission exists.
 */
bool validate_permission(uint16_t group_id, permission_enum_t perm);

/*
 * Input Validation Functions
 */

bool validate_slot(uint8_t slot);
bool validate_name(const char *name, size_t max_len);
bool validate_perm_count(uint8_t count);
bool validate_contents_len(uint16_t len);
bool validate_bool(uint8_t value);

#endif  /* __SECURITY_H__ */
