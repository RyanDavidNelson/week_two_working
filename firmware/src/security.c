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
    /* 0–~20 ms SCA desync jitter.
     * Two TRNG bytes → 16-bit value; range ~0–640 k cycles ≈ 0–20 ms.
     * Wider window means CPA requires proportionally more traces to
     * average out the key-schedule power signature. */
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
    /* Loop counter i in [0, len); constant-time for all inputs. */
    for (i = 0; i < len; i++) {
        p[i] = 0;
    }
}

/* ------------------------------------------------------------------ */
/* Security Halt                                                       */
/* ------------------------------------------------------------------ */

void security_halt(void)
{
    __disable_irq();
    /* Spin forever — no return. */
    while (1) {
        __asm volatile("NOP");
    }
}

/* ------------------------------------------------------------------ */
/* Hardware TRNG                                                       */
/* ------------------------------------------------------------------ */

int trng_init(void)
{
    uint32_t poll = 0;

    DL_TRNG_reset(TRNG);
    DL_TRNG_enable(TRNG);

    /* Wait for TRNG to be ready; halt if self-test never completes. */
    while (DL_TRNG_getClockDivider(TRNG) == 0) {
        if (++poll >= TRNG_POLL_LIMIT) {
            security_halt();
        }
    }
    return 0;
}

uint32_t trng_read_word(void)
{
    uint32_t poll = 0;

    DL_TRNG_generateData(TRNG);

    while (DL_TRNG_getStatus(TRNG) != DL_TRNG_STATUS_DATA_READY) {
        if (++poll >= TRNG_POLL_LIMIT) {
            security_halt();
        }
    }
    return DL_TRNG_getData(TRNG);
}

uint8_t trng_read_byte(void)
{
    /* Low byte of a fresh 32-bit word. */
    return (uint8_t)(trng_read_word() & 0xFFU);
}

/* ------------------------------------------------------------------ */
/* Authentication Functions                                            */
/* ------------------------------------------------------------------ */

bool secure_compare(const uint8_t *a, const uint8_t *b, size_t len)
{
    const uint8_t *pa  = (const uint8_t *)a;
    const uint8_t *pb  = (const uint8_t *)b;
    volatile uint8_t acc = 0;
    size_t i;
    /* Loop counter i in [0, len); constant-time for all inputs. */
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
    for (i = 0; i < global_perm_count; i++) {
        if (global_permissions[i].group_id == group_id &&
            global_permissions[i].perm     == (uint8_t)perm) {
            found_pass1 = true;
        }
    }

    /* Second pass. */
    for (j = 0; j < global_perm_count; j++) {
        if (global_permissions[j].group_id == group_id &&
            global_permissions[j].perm     == (uint8_t)perm) {
            found_pass2 = true;
        }
    }

    if ((bool)found_pass1 != (bool)found_pass2) {
        security_halt();
    }

    return (bool)found_pass1;
}

/* ------------------------------------------------------------------ */
/* Validation Functions                                                */
/* ------------------------------------------------------------------ */

bool validate_slot(uint8_t slot)
{
    return (slot < NUM_SLOTS);
}

bool validate_name(const char *name, size_t max_len)
{
    size_t i;

    if (name == NULL || max_len == 0) { return false; }

    /* Loop counter i in [0, max_len); terminates at null or max_len. */
    for (i = 0; i < max_len; i++) {
        if (name[i] == '\0') { return true; }
        if ((unsigned char)name[i] < 0x20 || (unsigned char)name[i] > 0x7E) {
            return false;
        }
    }
    /* No null terminator found within max_len — reject. */
    return false;
}

bool validate_perm_count(int count)
{
    return (count >= 0 && count <= MAX_PERM_COUNT);
}
