/**
 * @file security.c
 * @brief Security primitives implementation for eCTF HSM
 * @date 2026
 *
 * Key split: check_pin_cmp() uses PIN_KEY for HMAC.  PIN_KEY is a runtime
 *   key stored in flash; CPA against check_pin_cmp recovers PIN_KEY but not
 *   TRANSFER_AUTH_KEY (they are independent 256-bit values).
 *
 * FIX A (P1/P2): SECURE_PIN_CHECK and SECURE_BOOL_CHECK macros (in security.h)
 *   harden every call site branch.  This file implements the underlying
 *   single-evaluation primitives; double-evaluation happens at the macro.
 *
 * FIX B (P3/P6): check_pin_cmp() computes HMAC(PIN_KEY, input_pin || "pin")
 *   and compares with the stored PIN_HMAC constant.  Raw PIN not in flash.
 *
 * SCA JITTER: random_delay_wide() uses two TRNG bytes (16-bit range) for a
 *   0–~20 ms pre-key-load jitter window.  random_delay() (one byte, 0–~4 ms)
 *   is retained for glitch desynchronisation between double-evaluation passes.
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#include "security.h"
#include "crypto.h"
#include "secrets.h"
#include "filesystem.h"
#include "ti_msp_dl_config.h"
#include <ti/driverlib/dl_trng.h>
#include <ti/devices/msp/msp.h>

/* Maximum iterations for TRNG busy-wait polls. */
#define TRNG_POLL_LIMIT 1000000UL

/*
 * Timing Functions
 */

void delay_cycles(uint32_t cycles)
{
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
    /* Split into 100ms chunks to avoid uint32_t overflow. */
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
    /* 0–~4 ms jitter for glitch desynchronisation between double-eval passes.
     * One TRNG byte → 7-bit value × (CYCLES_PER_MS/8) cycles. */
    uint32_t jitter = (uint32_t)(trng_read_byte() & 0x7F) * (CYCLES_PER_MS / 8);
    delay_cycles(jitter);
}

void random_delay_wide(void)
{
    /* 0–~20 ms jitter for SCA pre-key-load desynchronisation.
     * Two TRNG bytes form a 16-bit value; scale to cycle count.
     * Range: 0 to 65535 × (CYCLES_PER_MS / ~3) ≈ 0–640k cycles ≈ 0–20 ms.
     * Wider window means CPA requires proportionally more traces. */
    uint32_t lo     = (uint32_t)trng_read_byte();
    uint32_t hi     = (uint32_t)trng_read_byte();
    uint32_t jitter = ((hi << 8) | lo) * (CYCLES_PER_MS / 3);
    delay_cycles(jitter);
}

/*
 * Memory Functions
 */

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

/*
 * Hardware TRNG Functions
 */

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

    /* Poll until clock divider confirms normal mode. */
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

    /* Poll until capture ready, with limit. */
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

/*
 * Memory Functions
 */

bool secure_compare(const void *a, const void *b, size_t len)
{
    const uint8_t *pa = (const uint8_t *)a;
    const uint8_t *pb = (const uint8_t *)b;
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
 * check_pin_cmp — HMAC-based PIN check, single pass, no brute-force penalty.
 *
 * Computes HMAC(PIN_KEY, pin || "pin") and compares with PIN_HMAC.
 * Called twice by SECURE_PIN_CHECK with random_delay() between passes.
 */
bool check_pin_cmp(const unsigned char *pin)
{
    uint8_t computed_mac[HMAC_SIZE];
    bool    result;

    if (pin == NULL) { return false; }

    if (hmac_sha256(PIN_KEY,
                    pin, PIN_LENGTH,
                    HMAC_DOMAIN_PIN,
                    computed_mac) != 0) {
        secure_zero(computed_mac, sizeof(computed_mac));
        return false;
    }

    result = secure_compare(computed_mac, PIN_HMAC, HMAC_SIZE);
    secure_zero(computed_mac, sizeof(computed_mac));

    return result;
}

/*
 * check_pin — double-pass check_pin_cmp with random_delay between;
 * halt if passes disagree, 5-second penalty on wrong PIN.
 */
bool check_pin(unsigned char *pin)
{
    volatile bool r1, r2;

    r1 = check_pin_cmp(pin);
    random_delay();
    r2 = check_pin_cmp(pin);

    if ((bool)r1 != (bool)r2) {
        security_halt();
    }

    if (!r1) {
        delay_ms(5000);
        return false;
    }

    return true;
}

bool validate_permission(uint16_t group_id, permission_enum_t perm)
{
    volatile bool found_pass1 = false;
    volatile bool found_pass2 = false;
    int i, j;

    /* First pass — loop counter i in [0, PERM_COUNT). */
    for (i = 0; i < PERM_COUNT; i++) {
        bool group_match = (global_permissions[i].group_id == group_id);
        bool has_perm    = false;

        switch (perm) {
        case PERM_READ:    has_perm = global_permissions[i].read;    break;
        case PERM_WRITE:   has_perm = global_permissions[i].write;   break;
        case PERM_RECEIVE: has_perm = global_permissions[i].receive; break;
        default: break;
        }

        if (group_match && has_perm) {
            found_pass1 = true;
        }
    }

    random_delay();

    /* Second pass — loop counter j in [0, PERM_COUNT). */
    for (j = 0; j < PERM_COUNT; j++) {
        bool group_match = (global_permissions[j].group_id == group_id);
        bool has_perm    = false;

        switch (perm) {
        case PERM_READ:    has_perm = global_permissions[j].read;    break;
        case PERM_WRITE:   has_perm = global_permissions[j].write;   break;
        case PERM_RECEIVE: has_perm = global_permissions[j].receive; break;
        default: break;
        }

        if (group_match && has_perm) {
            found_pass2 = true;
        }
    }

    /* Passes must agree; disagreement indicates fault injection. */
    if ((bool)found_pass1 != (bool)found_pass2) {
        security_halt();
    }

    return found_pass1;
}

/*
 * Input Validation Functions
 */

bool validate_slot(uint8_t slot)
{
    return (slot < MAX_FILE_COUNT);
}

bool validate_name(const char *name, size_t max_len)
{
    size_t i;

    if (name == NULL) { return false; }

    /* Loop counter i in [0, max_len); terminates at null or limit. */
    for (i = 0; i < max_len; i++) {
        char c = name[i];

        if (c == '\0') {
            return (i > 0); /* Must have at least one printable character. */
        }

        /* Printable ASCII only: 0x20 (space) through 0x7E (~). */
        if ((uint8_t)c < 0x20 || (uint8_t)c > 0x7E) {
            return false;
        }
    }

    /* Reached max_len without null terminator. */
    return false;
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
    return (value == 0u || value == 1u);
}
