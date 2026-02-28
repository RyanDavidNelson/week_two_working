/**
 * @file security.c
 * @brief Security primitives implementation for eCTF HSM
 * @date 2026
 *
 * This source file is part of an example system for MITRE's 2026 Embedded
 * CTF (eCTF). This code is being provided only for educational purposes for
 * the 2026 MITRE eCTF competition, and may not meet MITRE standards for
 * quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#include "security.h"
#include "crypto.h"
#include "secrets.h"
#include "ti_msp_dl_config.h"
#include <ti/driverlib/dl_trng.h>
#include <ti/devices/msp/msp.h>

/* Hard cap on TRNG busy-wait iterations; security_halt() if exceeded. */
#define TRNG_POLL_LIMIT 1000000UL

/* ------------------------------------------------------------------ */
/* Timing Functions                                                    */
/* ------------------------------------------------------------------ */

void delay_cycles(uint32_t cycles)
{
    /* Assembly delay from TI SDK dl_common.c — cycle-accurate busy wait. */
    uint32_t scratch;
    __asm volatile(
#ifdef __GNUC__
        ".syntax unified\n\t"
#endif
        "SUBS %0, %[numCycles], #2; \n"
        "%=: \n\t"
        "SUBS %0, %0, #4; \n\t"
        "NOP; \n\t"
        "BHS  %=b;"
        : "=&r"(scratch)
        : [numCycles] "r"(cycles));
}

void delay_ms(uint32_t ms)
{
    /* Split into 100 ms chunks to avoid uint32_t overflow on large delays. */
    while (ms >= 100) {
        delay_cycles(100 * CYCLES_PER_MS);
        ms -= 100;
    }
    if (ms > 0) {
        delay_cycles(ms * CYCLES_PER_MS);
    }
}

void random_delay(void)
{
    /* 0–~4 ms jitter from one TRNG byte.  Kept for future use but no longer
     * called on any hot path — double-glitch is out of scope, and timing
     * analysis is handled by the XOR accumulator + wolfcrypt bitsliced AES. */
    uint32_t jitter = (uint32_t)(trng_read_byte() & 0x7F) * (CYCLES_PER_MS / 32);
    delay_cycles(jitter);
}

void random_delay_wide(void)
{
    /* 0–~20 ms jitter for SCA pre-key-load desynchronisation.
     * Two TRNG bytes → 16-bit value; range ~0–640k cycles ≈ 0–20 ms.
     * Wider window means CPA requires proportionally more traces. */
    uint32_t lo     = (uint32_t)trng_read_byte();
    uint32_t hi     = (uint32_t)trng_read_byte();
    uint32_t jitter = ((hi << 8) | lo) * (CYCLES_PER_MS / 3277);
    delay_cycles(jitter);
}

/* ------------------------------------------------------------------ */
/* Memory Functions                                                    */
/* ------------------------------------------------------------------ */

void secure_zero(void *ptr, size_t len)
{
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    size_t i;
    /* Loop counter i in [0, len); terminates exactly when i == len. */
    for (i = 0; i < len; i++) {
        p[i] = 0;
    }
}

void security_halt(void)
{
    __disable_irq();
    while (1) { __asm volatile("nop"); }
}

/* ------------------------------------------------------------------ */
/* Hardware TRNG Functions                                             */
/* ------------------------------------------------------------------ */

int trng_init(void)
{
    uint32_t poll_i;

    DL_TRNG_enablePower(TRNG);
#ifdef POWER_STARTUP_DELAY
    delay_cycles(POWER_STARTUP_DELAY);
#else
    delay_cycles(32000);
#endif

    DL_TRNG_setClockDivider(TRNG, DL_TRNG_CLOCK_DIVIDE_2);
    DL_TRNG_sendCommand(TRNG, DL_TRNG_CMD_NORM_FUNC);

    /* Poll until the clock divider register confirms normal-function mode.
     * Loop counter poll_i in [0, TRNG_POLL_LIMIT). */
    for (poll_i = 0;
         DL_TRNG_getClockDivider(TRNG) != DL_TRNG_CLOCK_DIVIDE_2 &&
         poll_i < TRNG_POLL_LIMIT;
         poll_i++) {}

    if (poll_i >= TRNG_POLL_LIMIT) {
        security_halt();
    }

    return 0;
}

uint32_t trng_read_word(void)
{
    uint32_t poll_i;

    DL_TRNG_sendCommand(TRNG, DL_TRNG_CMD_NORM_FUNC);

    /* Poll until capture-ready flag is set.
     * Loop counter poll_i in [0, TRNG_POLL_LIMIT). */
    for (poll_i = 0;
         !DL_TRNG_isCaptureReady(TRNG) && poll_i < TRNG_POLL_LIMIT;
         poll_i++) {}

    if (poll_i >= TRNG_POLL_LIMIT) {
        security_halt();
    }

    return DL_TRNG_getCapture(TRNG);
}

uint8_t trng_read_byte(void)
{
    return (uint8_t)(trng_read_word() & 0xFF);
}

/* ------------------------------------------------------------------ */
/* Authentication Functions                                            */
/* ------------------------------------------------------------------ */

bool secure_compare(const void *a, const void *b, size_t len)
{
    const uint8_t *pa  = (const uint8_t *)a;
    const uint8_t *pb  = (const uint8_t *)b;
    uint8_t        acc = 0;
    size_t         i;

    /* XOR accumulator: acc == 0 iff all bytes equal.
     * Loop counter i in [0, len); constant-time for all inputs. */
    for (i = 0; i < len; i++) {
        acc |= pa[i] ^ pb[i];
    }

    return (acc == 0);
}

/*
 * check_pin_cmp — single-pass HMAC-based PIN check, no brute-force penalty.
 *
 * Receives the PIN as PIN_LENGTH ASCII hex bytes exactly as the host sent
 * them (e.g. "1a2b3c").  Computes HMAC(PIN_KEY, pin || "pin") and
 * constant-time compares with PIN_HMAC stored in secrets.c.
 *
 * Never call this directly from a command handler — always use check_pin(),
 * which double-evaluates and applies the 5-second failure penalty.
 */
bool check_pin_cmp(const unsigned char *pin)
{
    uint8_t computed[HMAC_SIZE];
    bool    result;

    if (pin == NULL) { return false; }

    if (hmac_sha256(PIN_KEY,
                    pin, PIN_LENGTH,
                    HMAC_DOMAIN_PIN,
                    computed) != 0) {
        secure_zero(computed, sizeof(computed));
        return false;
    }

    result = secure_compare(computed, PIN_HMAC, HMAC_SIZE);
    secure_zero(computed, sizeof(computed));
    return result;
}

/*
 * check_pin — double-pass check_pin_cmp with no random delay between passes.
 *
 * The double-pass catches any single fault injection that flips the result of
 * one evaluation; both passes must agree or we halt.  random_delay() between
 * passes is not needed because double-glitch attacks are out of scope.
 *
 * Applies 5-second penalty on wrong PIN; zeros pin buffer on every exit path.
 */
bool check_pin(unsigned char *pin)
{
    volatile bool r1;
    volatile bool r2;

    r1 = check_pin_cmp(pin);
    r2 = check_pin_cmp(pin);   /* no random_delay — double-glitch out of scope */

    secure_zero(pin, PIN_LENGTH);

    if ((bool)r1 != (bool)r2) {
        security_halt();
    }

    if (!r1) {
        delay_ms(5000);
        return false;
    }

    return true;
}

/*
 * validate_permission — double-pass local permission check.
 *
 * Scans global_permissions[] twice without random_delay between passes.
 * A single fault injection that flips found_pass1 but not found_pass2 (or
 * vice-versa) is caught by the agreement check; security_halt() fires.
 * random_delay() removed — double-glitch is out of scope.
 *
 * Loop counter i in [0, PERM_COUNT); terminates when i == PERM_COUNT.
 * Loop counter j in [0, PERM_COUNT); terminates when j == PERM_COUNT.
 */
bool validate_permission(uint16_t group_id, permission_enum_t perm)
{
    volatile bool found_pass1 = false;
    volatile bool found_pass2 = false;
    int           i, j;

    /* First pass. */
    for (i = 0; i < PERM_COUNT; i++) {
        bool group_match = (global_permissions[i].group_id == group_id);
        bool has_perm    = false;

        switch (perm) {
        case PERM_READ:    has_perm = global_permissions[i].read;    break;
        case PERM_WRITE:   has_perm = global_permissions[i].write;   break;
        case PERM_RECEIVE: has_perm = global_permissions[i].receive; break;
        default: break;
        }

        if (group_match && has_perm) { found_pass1 = true; }
    }

    /* Second pass — no random_delay between passes. */
    for (j = 0; j < PERM_COUNT; j++) {
        bool group_match = (global_permissions[j].group_id == group_id);
        bool has_perm    = false;

        switch (perm) {
        case PERM_READ:    has_perm = global_permissions[j].read;    break;
        case PERM_WRITE:   has_perm = global_permissions[j].write;   break;
        case PERM_RECEIVE: has_perm = global_permissions[j].receive; break;
        default: break;
        }

        if (group_match && has_perm) { found_pass2 = true; }
    }

    /* Passes must agree; disagreement indicates a fault injection attempt. */
    if ((bool)found_pass1 != (bool)found_pass2) {
        security_halt();
    }

    return found_pass1;
}

/* ------------------------------------------------------------------ */
/* Input Validation Functions                                          */
/* ------------------------------------------------------------------ */

bool validate_slot(uint8_t slot)
{
    return (slot < MAX_FILE_COUNT);
}

bool validate_name(const char *name, size_t max_len)
{
    size_t i;

    if (name == NULL) { return false; }

    /* Loop counter i in [0, max_len); terminates on null or bound. */
    for (i = 0; i < max_len; i++) {
        char c = name[i];

        if (c == '\0') {
            return (i > 0);  /* Must have at least one character before null. */
        }

        /* Only printable ASCII 0x20–0x7E. */
        if ((unsigned char)c < 0x20 || (unsigned char)c > 0x7E) {
            return false;
        }
    }

    return false;  /* No null terminator found within max_len bytes. */
}

bool validate_perm_count(uint8_t count)
{
    return (count <= MAX_PERMS);
}

bool validate_contents_len(uint16_t len)
{
    return (len <= MAX_CONTENTS_SIZE);
}

bool validate_bool(uint8_t value)
{
    return (value == 0 || value == 1);
}
