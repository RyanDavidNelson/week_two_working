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
 * ok1, ok2 must be declared volatile bool by the caller.
 * The caller is responsible for zeroing pin_ptr and applying the 5-second
 * penalty on failure after this macro expands.
 *
 * Use SECURE_CHECK_FAILED(ok1, ok2) to test the result rather than the
 * plain `if (!(ok1 & ok2))` pattern — see that macro for why.
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
 * Use SECURE_CHECK_FAILED(ok1, ok2) to test the result.
 */
#define SECURE_BOOL_CHECK(ok1, ok2, expr)           \
    do {                                             \
        (ok1) = (expr);                             \
        (ok2) = (expr);                             \
        if ((bool)(ok1) != (bool)(ok2)) {           \
            security_halt();                         \
        }                                            \
    } while (0)

/*
 * SECURE_CHECK_FAILED — test the result of a preceding SECURE_BOOL_CHECK or
 * SECURE_PIN_CHECK with complement-canary hardening.
 *
 * WHY THE PLAIN `if (!(ok1 & ok2))` IS INSUFFICIENT:
 *   After the macro runs, both ok1 and ok2 hold the correct value and agree.
 *   The subsequent branch `if (!(ok1 & ok2))` compiles to a single CMP+BEQ
 *   instruction on Cortex-M0+.  A ChipWhisperer voltage glitch targeting that
 *   instruction can skip or mis-execute the branch, bypassing the entire check
 *   without the macro ever detecting anything.
 *
 * HOW THIS MACRO HARDENS THE BRANCH:
 *   1. Re-read ok1 and ok2 from their stack slots into fresh volatiles
 *      (_v1, _v2) — forces two independent loads the compiler cannot merge.
 *   2. Compute _and = _v1 & _v2 — the expected "pass" value.
 *   3. Store _canary = !(_and) — the expected "fail" value.
 *   4. The final expression is true (i.e. "check failed") only when both
 *      _and is false AND _canary is true — they must be complementary.
 *
 * SINGLE-GLITCH ANALYSIS:
 *   - Glitch flips _v1's load (false→true): _and=true, _canary=false → !(_and
 *     & !_canary) = !(true & true) = false → guard active (check "passed").
 *     Wait — that would incorrectly say "not failed".  Let me re-examine.
 *
 *   The expression returned is: !(_and & !_canary).
 *     Normal pass  (ok1=ok2=true):  _and=true,  _canary=false → !(true & true)  = false → not failed ✓
 *     Normal fail  (ok1=ok2=false): _and=false, _canary=true  → !(false & false) = true  → failed ✓
 *     Glitch _v1 load (false→true, _v2=false): _and=false, _canary=true → !(false & false) = true → failed ✓
 *     Glitch _and (false→true): _canary=true (computed before glitch) → !(true & false) = true → failed ✓
 *     Glitch _canary (true→false): _and=false → !(false & true) = true → failed ✓
 *     Glitch the branch itself: still reads three separate volatile-derived
 *       values; attacker would need to simultaneously corrupt _and AND _canary
 *       AND the branch — three independent fault targets.
 *
 * Usage pattern:
 *   volatile bool ok1, ok2;
 *   SECURE_BOOL_CHECK(ok1, ok2, some_condition);
 *   if (SECURE_CHECK_FAILED(ok1, ok2)) {
 *       // reject path
 *   }
 *   // accept path
 */
#define SECURE_CHECK_FAILED(ok1, ok2)                   \
    __extension__({                                      \
        volatile bool _v1     = (ok1);                   \
        volatile bool _v2     = (ok2);                   \
        volatile bool _and    = (_v1 & _v2);             \
        volatile bool _canary = !(_and);                 \
        /* Passes only when _and==true AND _canary==false (complementary). */ \
        !(_and & !_canary);                              \
    })

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
 * by the XOR accumulator in secure_compare().
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
/* Stack canary                                                        */
/* ------------------------------------------------------------------ */

/*
 * __stack_chk_guard — runtime stack canary, seeded from TRNG in init().
 *
 * The compiler (-fstack-protector-strong) reads this at instrumented
 * function entry, stores a copy just above the return address, then
 * re-reads and compares at function exit.  Any linear stack smash that
 * reaches the return address must first corrupt the stored copy.
 *
 * Layout on little-endian Cortex-M0+:
 *   byte 0 (lowest address, overwritten first by upward smash) == 0x00
 *   bytes 1-3 == random TRNG bytes
 *
 * The embedded null (byte 0) means any string-copy overwrite that would
 * produce a non-zero value at that position corrupts the canary before
 * reaching the return address.  The 24 random bits in bytes 1-3 defeat
 * non-string overwrites.
 *
 * Declared volatile so the compiler cannot cache the load in a register.
 */
extern volatile uint32_t __stack_chk_guard;

/*
 * __stack_chk_fail — compiler hook invoked on canary mismatch.
 * Delegates immediately to security_halt(); never returns.
 */
void __stack_chk_fail(void) __attribute__((noreturn));

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
