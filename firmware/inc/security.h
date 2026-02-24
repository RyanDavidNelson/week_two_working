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
 *  SCA JITTER — random_delay_wide() for pre-key-load desynchronisation.
 *    Uses two TRNG bytes for a 0–~20 ms window, substantially wider than
 *    random_delay() (0–~4 ms).  Called in crypto.c before every
 *    DL_AESADV_setKeyAligned() to slide the key-load power spike.
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

/**
 * @brief Short random jitter: 0–~4 ms from one TRNG byte.
 *
 * Used between double-evaluation passes in SECURE_PIN_CHECK and
 * SECURE_BOOL_CHECK to desynchronise fault-injection timing.
 */
void     random_delay(void);

/**
 * @brief Wide random jitter: 0–~20 ms from two TRNG bytes.
 *
 * Called in crypto.c immediately before each DL_AESADV_setKeyAligned()
 * to slide the key-load power spike across a larger trace window.
 * Wider range means CPA needs more traces to average through the noise.
 */
void     random_delay_wide(void);

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
bool     secure_compare(const void *a, const void *b, size_t len);

/** Single-pass HMAC-based PIN check (no penalty). */
bool     check_pin_cmp(const unsigned char *pin);

/** Double-pass PIN check with 5-second penalty on failure. */
bool     check_pin(unsigned char *pin);

/** Double-pass permission lookup; halts on disagreement. */
bool     validate_permission(uint16_t group_id, permission_enum_t perm);

bool     validate_slot(uint8_t slot);
bool     validate_name(const char *name, size_t max_len);
bool     validate_perm_count(uint8_t count);
bool     validate_contents_len(uint16_t len);
bool     validate_bool(uint8_t value);

/* Note: validate_perm_bytes() is static in commands.c — not declared here. */

#endif  /* __SECURITY_H__ */
