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

/*
 * SECURE_PIN_CHECK — double-evaluate check_pin_cmp() with no delay between
 * passes.  Halts device on disagreement (single-glitch bypass still requires
 * a double-glitch to defeat both passes simultaneously).
 *
 * random_delay() was removed: we do not defend against double-glitch attacks,
 * and timing/power analysis on the PIN path is handled by the XOR accumulator
 * in secure_compare() and wolfcrypt's bitsliced AES.
 *
 * ok1, ok2 must be declared volatile bool by the caller.
 * The caller is responsible for zeroing pin_ptr and applying the 5-second
 * penalty on failure after this macro expands.
 */
#define SECURE_PIN_CHECK(ok1, ok2, pin_ptr)         \
    do {                                             \
        (ok1) = check_pin_cmp(pin_ptr);             \
        (ok2) = check_pin_cmp(pin_ptr);             \
        if ((bool)(ok1) != (bool)(ok2)) {           \
            security_halt();                         \
        }                                            \
    } while (0)

/*
 * SECURE_BOOL_CHECK — double-evaluate any side-effect-free boolean
 * expression with no delay between passes.
 * Halts device on disagreement (single fault injection still caught).
 *
 * random_delay() removed for same reasons as SECURE_PIN_CHECK.
 */
#define SECURE_BOOL_CHECK(ok1, ok2, expr)           \
    do {                                             \
        (ok1) = (expr);                             \
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
 * Available for future use.  No longer called on any hot path —
 * double-glitch defence is out of scope and timing analysis is handled
 * by the XOR accumulator.
 */
void random_delay(void);

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
 *        Never call directly — always use SECURE_PIN_CHECK or check_pin().
 */
bool check_pin_cmp(const unsigned char *pin);

/**
 * @brief Double-pass PIN check with 5-second failure penalty.
 *        Zeros pin buffer on all exit paths.
 */
bool check_pin(unsigned char *pin);

/**
 * @brief Double-pass permission check for local group permissions.
 *        Halts on pass disagreement (single-fault resistance).
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

#endif /* __SECURITY_H__ */
