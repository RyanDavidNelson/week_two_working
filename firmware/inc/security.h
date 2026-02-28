/**
 * @file security.h
 * @brief Security primitives for eCTF HSM
 * @date 2026
 *
 * This source file is part of an example system for MITRE's 2026 Embedded
 * CTF (eCTF). This code is being provided only for educational purposes for
 * the 2026 MITRE eCTF competition, and may not meet MITRE standards for
 * quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#ifndef SECURITY_H
#define SECURITY_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* CPU frequency assumed by delay helpers. */
#define CPU_FREQ_HZ     32000000UL
#define CYCLES_PER_MS   (CPU_FREQ_HZ / 1000UL)

/* ------------------------------------------------------------------ */
/* Permission Types                                                    */
/* ------------------------------------------------------------------ */

typedef enum {
    PERM_READ    = 0,
    PERM_WRITE   = 1,
    PERM_RECEIVE = 2,
} permission_enum_t;

/* Maximum number of permission entries in the table. */
#define MAX_PERMS       8

/*
 * One permission entry: boolean flags per operation.
 * Wire format: group_id(2 LE) || read(1) || write(1) || receive(1).
 * Must match secrets_to_c_header.py serialization.
 */
typedef struct {
    uint16_t group_id;
    bool     read;
    bool     write;
    bool     receive;
} group_permission_t;

/* Populated at boot from the stored permission table in secrets.c. */
extern const group_permission_t global_permissions[MAX_PERMS];
extern int                      global_perm_count;

/* ------------------------------------------------------------------ */
/* Slot / Name / Content Constants                                     */
/* ------------------------------------------------------------------ */

#define NUM_SLOTS           8
#define MAX_NAME_SIZE       32
#define MAX_CONTENTS_SIZE   8192
#define PIN_LENGTH          6

/* ------------------------------------------------------------------ */
/* Glitch-Resistant Check Macros                                       */
/* ------------------------------------------------------------------ */

/**
 * @brief Double-evaluate a boolean expression and halt on disagreement.
 *
 * Evaluates expr twice into ok1 and ok2.  If the two volatile results
 * differ, a fault injection is assumed and security_halt() is called.
 */
#define SECURE_BOOL_CHECK(ok1, ok2, expr)           \
    do {                                             \
        (ok1) = (expr);                             \
        (ok2) = (expr);                             \
        if ((bool)(ok1) != (bool)(ok2)) {           \
            security_halt();                         \
        }                                            \
    } while (0)

/**
 * @brief Double-evaluate check_pin() and halt on disagreement.
 *        Zeroing of pin buffer is handled inside check_pin().
 */
#define SECURE_PIN_CHECK(ok1, ok2, pin_buf)                     \
    do {                                                         \
        (ok1) = check_pin((unsigned char *)(pin_buf));          \
        (ok2) = check_pin_cmp((const unsigned char *)(pin_buf));\
        if ((bool)(ok1) != (bool)(ok2)) {                       \
            security_halt();                                     \
        }                                                        \
    } while (0)

/* ------------------------------------------------------------------ */
/* Timing Functions                                                    */
/* ------------------------------------------------------------------ */

/** Calibrated busy-wait; pattern from TI SDK dl_common.c. */
void delay_cycles(uint32_t cycles);

/** Millisecond busy-wait; chunked to avoid uint32_t overflow. */
void delay_ms(uint32_t ms);

/**
 * @brief Random jitter: 0–~20 ms from two TRNG bytes.
 *
 * Called in crypto.c before every wc_AesGcmSetKey() to slide the
 * key-schedule power signature across a ~20 ms trace window.
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
bool secure_compare(const uint8_t *a, const uint8_t *b, size_t len);

/**
 * @brief HMAC-based PIN verification with 5-second failure penalty.
 *        Double-evaluates and halts on fault-injection mismatch.
 *        Zeroes the pin buffer on every exit path.
 */
bool check_pin(unsigned char *pin);

/**
 * @brief Single-pass HMAC PIN check.  Never call directly from a handler —
 *        always use check_pin() which double-evaluates and penalises.
 */
bool check_pin_cmp(const unsigned char *pin);

/* ------------------------------------------------------------------ */
/* Validation Functions                                                */
/* ------------------------------------------------------------------ */

/** Returns true iff slot is in [0, NUM_SLOTS). */
bool validate_slot(uint8_t slot);

/** Returns true iff name contains only printable ASCII and is null-terminated
 *  within max_len bytes. */
bool validate_name(const char *name, size_t max_len);

/** Returns true iff count is in [0, MAX_PERMS]. */
bool validate_perm_count(int count);

/**
 * @brief Double-pass scan of global_permissions[] for (group_id, perm).
 *        Checks the read/write/receive boolean field corresponding to perm.
 *        Halts if the two passes disagree (fault injection defence).
 */
bool validate_permission(uint16_t group_id, permission_enum_t perm);

#endif /* SECURITY_H */
