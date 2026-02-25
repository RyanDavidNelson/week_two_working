/**
 * @file security.h
 * @brief Security primitives for eCTF HSM
 * @date 2026
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */
#ifndef __SECURITY_H__
#define __SECURITY_H__

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

/* ------------------------------------------------------------------ */
/* Constants                                                           */
/* ------------------------------------------------------------------ */

#define MAX_PERMS         8
#define MAX_FILE_COUNT    8
#define MAX_NAME_SIZE     32
#define MAX_CONTENTS_SIZE 8192

/* PIN is exactly 6 lowercase hex ASCII characters as received from host
 * (e.g. "1a2b3c").  check_pin_cmp() passes these 6 bytes directly to
 * hmac_sha256(); secrets_to_c_header.py must use pin.encode('ascii') so
 * the build-time PIN_HMAC matches what the runtime computes. */
#define PIN_LENGTH    6

/* MSPM0L2228 runs at 32 MHz. */
#define CYCLES_PER_MS 32000

/* ------------------------------------------------------------------ */
/* Types                                                               */
/* ------------------------------------------------------------------ */

typedef enum {
    PERM_READ    = 'R',
    PERM_WRITE   = 'W',
    PERM_RECEIVE = 'C',
} permission_enum_t;

typedef struct {
    uint16_t group_id;
    bool     read;
    bool     write;
    bool     receive;
} group_permission_t;

/* ------------------------------------------------------------------ */
/* Glitch-hardening macros                                             */
/* ------------------------------------------------------------------ */

/**
 * SECURE_PIN_CHECK — double-evaluate check_pin_cmp() with random_delay()
 * between passes.  Halts device on disagreement (single-glitch bypass
 * becomes a required double-glitch).
 *
 * ok1, ok2 must be declared volatile bool by the caller.
 * The caller is responsible for zeroing pin_ptr and applying the 5-second
 * penalty on failure after this macro expands.
 */
#define SECURE_PIN_CHECK(ok1, ok2, pin_ptr)         \
    do {                                             \
        (ok1) = check_pin_cmp(pin_ptr);             \
        random_delay();                              \
        (ok2) = check_pin_cmp(pin_ptr);             \
        if ((bool)(ok1) != (bool)(ok2)) {           \
            security_halt();                         \
        }                                            \
    } while (0)

/**
 * SECURE_BOOL_CHECK — double-evaluate any side-effect-free boolean
 * expression with random_delay() between passes.
 * Halts device on disagreement.
 */
#define SECURE_BOOL_CHECK(ok1, ok2, expr)           \
    do {                                             \
        (ok1) = (expr);                             \
        random_delay();                              \
        (ok2) = (expr);                             \
        if ((bool)(ok1) != (bool)(ok2)) {           \
            security_halt();                         \
        }                                            \
    } while (0)

/* ------------------------------------------------------------------ */
/* Timing Functions                                                    */
/* ------------------------------------------------------------------ */

/** Calibrated busy-wait; pattern from TI SDK dl_common.c. */
void delay_cycles(uint32_t cycles);

/** Millisecond busy-wait; chunked to avoid uint32_t overflow. */
void delay_ms(uint32_t ms);

/**
 * @brief Short random jitter: 0–~4 ms from one TRNG byte.
 *
 * Used between double-evaluation passes in SECURE_PIN_CHECK and
 * SECURE_BOOL_CHECK to desynchronise fault-injection timing.
 */
void random_delay(void);

/**
 * @brief Wide random jitter: 0–~20 ms from two TRNG bytes.
 *
 * Called in crypto.c before every DL_AESADV_setKeyAligned() to slide the
 * key-load power spike across a larger trace window.  Wider range means
 * CPA needs proportionally more traces to average through the noise.
 */
void random_delay_wide(void);

/* ------------------------------------------------------------------ */
/* Memory Functions                                                    */
/* ------------------------------------------------------------------ */

/** Volatile-pointer zero — not optimised away by the compiler. */
void secure_zero(void *ptr, size_t len);

/** Disable IRQ and spin forever.  Called on any security invariant breach. */
void security_halt(void) __attribute__((noreturn));

/* ------------------------------------------------------------------ */
/* Hardware TRNG Functions                                             */
/* ------------------------------------------------------------------ */

/** Initialise TRNG; calls security_halt() if self-test exceeds poll limit. */
int      trng_init(void);

/** Read one 32-bit word from TRNG; security_halt() on poll timeout. */
uint32_t trng_read_word(void);

/** Read one byte from TRNG (low byte of trng_read_word()). */
uint8_t  trng_read_byte(void);

/* ------------------------------------------------------------------ */
/* Authentication Functions                                            */
/* ------------------------------------------------------------------ */

/**
 * @brief Constant-time byte comparison.  XOR accumulator, no early exit.
 *        Used for all HMAC tag comparisons.
 */
bool secure_compare(const void *a, const void *b, size_t len);

/**
 * @brief Single-pass HMAC-based PIN check.  No brute-force penalty.
 *
 * Computes HMAC(PIN_KEY, pin[PIN_LENGTH] || "pin") and constant-time
 * compares with PIN_HMAC from flash.  Never called directly by command
 * handlers — always invoked through check_pin() which double-evaluates.
 *
 * @param pin  Exactly PIN_LENGTH bytes as received from the host (the 6
 *             ASCII hex characters, e.g. "1a2b3c").
 */
bool check_pin_cmp(const unsigned char *pin);

/**
 * @brief Double-pass PIN check with 5-second penalty on failure.
 *
 * Calls check_pin_cmp() twice with random_delay() between passes.
 * Calls security_halt() if passes disagree.
 * Zeros the pin buffer on every exit path.
 */
bool check_pin(unsigned char *pin);

/**
 * @brief Double-pass permission lookup; calls security_halt() on disagreement.
 */
bool validate_permission(uint16_t group_id, permission_enum_t perm);

/* ------------------------------------------------------------------ */
/* Input Validation Functions                                          */
/* ------------------------------------------------------------------ */

bool validate_slot(uint8_t slot);
bool validate_name(const char *name, size_t max_len);
bool validate_perm_count(uint8_t count);
bool validate_contents_len(uint16_t len);
bool validate_bool(uint8_t value);

#endif  /* __SECURITY_H__ */
