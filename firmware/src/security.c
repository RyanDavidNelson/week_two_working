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

/* Runtime permission count; initialised at boot from PERM_COUNT. */
int global_perm_count = PERM_COUNT;

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
     * Two TRNG bytes → 16-bit value; range ~0–640 k cycles ≈ 0–20 ms. */
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
    uint32_t poll;

    DL_TRNG_sendCommand(TRNG, DL_TRNG_CMD_TEST_DIG);
    for (poll = 0; poll < TRNG_POLL_LIMIT; poll++) {
        if (DL_TRNG_getInterruptStatus(TRNG) &
            DL_TRNG_INTERRUPT_CMD_DONE_EVENT) {
            break;
        }
    }
    if (poll >= TRNG_POLL_LIMIT) { security_halt(); }
    DL_TRNG_clearInterruptStatus(TRNG, DL_TRNG_INTERRUPT_CMD_DONE_EVENT);

    DL_TRNG_sendCommand(TRNG, DL_TRNG_CMD_TEST_ANA);
    for (poll = 0; poll < TRNG_POLL_LIMIT; poll++) {
        if (DL_TRNG_getInterruptStatus(TRNG) &
            DL_TRNG_INTERRUPT_CMD_DONE_EVENT) {
            break;
        }
    }
    if (poll >= TRNG_POLL_LIMIT) { security_halt(); }
    DL_TRNG_clearInterruptStatus(TRNG, DL_TRNG_INTERRUPT_CMD_DONE_EVENT);

    DL_TRNG_sendCommand(TRNG, DL_TRNG_CMD_NORM_FUNC);
    return 0;
}

uint32_t trng_read_word(void)
{
    uint32_t poll;

    DL_TRNG_sendCommand(TRNG, DL_TRNG_CMD_NORM_FUNC);
    for (poll = 0; poll < TRNG_POLL_LIMIT; poll++) {
        if (DL_TRNG_getInterruptStatus(TRNG) &
            DL_TRNG_INTERRUPT_CAPTURE_RDY_EVENT) {
            break;
        }
    }
    if (poll >= TRNG_POLL_LIMIT) { security_halt(); }

    uint32_t word = DL_TRNG_getCapture(TRNG);
    DL_TRNG_clearInterruptStatus(TRNG, DL_TRNG_INTERRUPT_CAPTURE_RDY_EVENT);
    return word;
}

uint8_t trng_read_byte(void)
{
    return (uint8_t)(trng_read_word() & 0xFF);
}

/* ------------------------------------------------------------------ */
/* Authentication Functions                                            */
/* ------------------------------------------------------------------ */

bool secure_compare(const uint8_t *a, const uint8_t *b, size_t len)
{
    volatile uint8_t diff = 0;
    size_t i;
    /* Loop counter i in [0, len); no early exit — constant time. */
    for (i = 0; i < len; i++) {
        diff |= a[i] ^ b[i];
    }
    return (diff == 0);
}

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
 * check_pin — double-pass check_pin_cmp with 5-second penalty on failure.
 *
 * Both passes must agree or security_halt() fires (fault injection defence).
 * Zeroes pin buffer on every exit path.
 */
bool check_pin(unsigned char *pin)
{
    volatile bool r1;
    volatile bool r2;

    r1 = check_pin_cmp(pin);
    r2 = check_pin_cmp(pin);

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
 * Selects the read/write/receive boolean field of group_permission_t
 * based on the permission_enum_t argument, then scans global_permissions[]
 * twice.  A single fault injection that flips one pass but not the other
 * is caught by the agreement check; security_halt() fires.
 *
 * Loop counter i in [0, global_perm_count); terminates when i == global_perm_count.
 * Loop counter j in [0, global_perm_count); terminates when j == global_perm_count.
 */
bool validate_permission(uint16_t group_id, permission_enum_t perm)
{
    volatile bool found_pass1 = false;
    volatile bool found_pass2 = false;
    int           i, j;

    /* First pass. */
    for (i = 0; i < global_perm_count; i++) {
        if (global_permissions[i].group_id != group_id) { continue; }
        bool granted;
        if      (perm == PERM_READ)    { granted = global_permissions[i].read;    }
        else if (perm == PERM_WRITE)   { granted = global_permissions[i].write;   }
        else if (perm == PERM_RECEIVE) { granted = global_permissions[i].receive; }
        else                           { granted = false; }
        if (granted) { found_pass1 = true; }
    }

    /* Second pass — identical logic; disagreement implies fault injection. */
    for (j = 0; j < global_perm_count; j++) {
        if (global_permissions[j].group_id != group_id) { continue; }
        bool granted;
        if      (perm == PERM_READ)    { granted = global_permissions[j].read;    }
        else if (perm == PERM_WRITE)   { granted = global_permissions[j].write;   }
        else if (perm == PERM_RECEIVE) { granted = global_permissions[j].receive; }
        else                           { granted = false; }
        if (granted) { found_pass2 = true; }
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
    return (count >= 0 && count <= MAX_PERMS);
}
