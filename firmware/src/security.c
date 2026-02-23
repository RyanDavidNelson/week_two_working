/**
 * @file security.c
 * @brief Security primitives implementation for eCTF HSM
 * @date 2026
 *
 * FIX A (P1/P2): SECURE_PIN_CHECK and SECURE_BOOL_CHECK macros (in security.h)
 *   harden every call site branch.  This file implements the underlying
 *   single-evaluation primitives; the double-evaluation happens at the macro
 *   expansion in commands.c.
 *
 * FIX B (P3/P6): check_pin_cmp() replaces direct XOR comparison.
 *   It computes HMAC(AUTH_KEY, input_pin || "pin") and compares with the
 *   stored PIN_HMAC constant.  The raw PIN string is no longer in .rodata;
 *   an attacker who dumps flash obtains only the HMAC output, which gives
 *   no direct XOR target for classical CPA.  The wolfcrypt SHA-256
 *   compression function mixes the PIN bits through non-linear S-boxes,
 *   breaking single-byte Hamming-weight correlation.
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
    /* 0–~4 ms random jitter for glitch desynchronisation. */
    uint32_t jitter = (trng_read_byte() & 0x7F) * (CYCLES_PER_MS / 8);
    delay_cycles(jitter);
}

/*
 * Memory Functions
 */

void secure_zero(void *ptr, size_t len)
{
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    size_t i;
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

    /* Digital self-test. */
    DL_TRNG_sendCommand(TRNG, DL_TRNG_CMD_TEST_DIG);
    for (poll_i = 0; poll_i < TRNG_POLL_LIMIT; poll_i++) {
        if (DL_TRNG_isCommandDone(TRNG)) break;
    }
    if (poll_i >= TRNG_POLL_LIMIT) { security_halt(); }
    DL_TRNG_clearInterruptStatus(TRNG, DL_TRNG_INTERRUPT_CMD_DONE_EVENT);

    delay_cycles(100000);

    if (DL_TRNG_getDigitalHealthTestResults(TRNG) !=
            DL_TRNG_DIGITAL_HEALTH_TEST_SUCCESS) {
        return -1;
    }

    /* Analog self-test. */
    DL_TRNG_sendCommand(TRNG, DL_TRNG_CMD_TEST_ANA);
    for (poll_i = 0; poll_i < TRNG_POLL_LIMIT; poll_i++) {
        if (DL_TRNG_isCommandDone(TRNG)) break;
    }
    if (poll_i >= TRNG_POLL_LIMIT) { security_halt(); }
    DL_TRNG_clearInterruptStatus(TRNG, DL_TRNG_INTERRUPT_CMD_DONE_EVENT);

    delay_cycles(100000);

    if (DL_TRNG_getAnalogHealthTestResults(TRNG) !=
            DL_TRNG_ANALOG_HEALTH_TEST_SUCCESS) {
        return -2;
    }

    /* Enter normal operation. */
    DL_TRNG_sendCommand(TRNG, DL_TRNG_CMD_NORM_FUNC);
    for (poll_i = 0; poll_i < TRNG_POLL_LIMIT; poll_i++) {
        if (DL_TRNG_isCommandDone(TRNG)) break;
    }
    if (poll_i >= TRNG_POLL_LIMIT) { security_halt(); }
    DL_TRNG_clearInterruptStatus(TRNG, DL_TRNG_INTERRUPT_CMD_DONE_EVENT);

    DL_TRNG_setDecimationRate(TRNG, DL_TRNG_DECIMATION_RATE_4);

    return 0;
}

uint32_t trng_read_word(void)
{
    uint32_t poll_i;

    for (poll_i = 0; poll_i < TRNG_POLL_LIMIT; poll_i++) {
        if (DL_TRNG_isCaptureReady(TRNG)) break;
    }
    if (poll_i >= TRNG_POLL_LIMIT) { security_halt(); }

    uint32_t value = DL_TRNG_getCapture(TRNG);
    DL_TRNG_clearInterruptStatus(TRNG, DL_TRNG_INTERRUPT_CAPTURE_RDY_EVENT);
    DL_TRNG_sendCommand(TRNG, DL_TRNG_CMD_NORM_FUNC);

    return value;
}

uint8_t trng_read_byte(void)
{
    static uint32_t cached_word     = 0;
    static uint8_t  bytes_remaining = 0;

    if (bytes_remaining == 0) {
        cached_word     = trng_read_word();
        bytes_remaining = 4;
    }

    uint8_t result  = (uint8_t)(cached_word & 0xFF);
    cached_word   >>= 8;
    bytes_remaining--;

    return result;
}

/*
 * Authentication Functions
 */

bool secure_compare(const void *a, const void *b, size_t len)
{
    const volatile uint8_t *pa = (const volatile uint8_t *)a;
    const volatile uint8_t *pb = (const volatile uint8_t *)b;
    volatile uint8_t result = 0;
    size_t i;

    for (i = 0; i < len; i++) {
        result |= pa[i] ^ pb[i];
    }

    return (result == 0);
}

/**
 * FIX B: HMAC-based PIN comparison.
 *
 * Computes HMAC(AUTH_KEY, pin || "pin") and compares with PIN_HMAC.
 * No raw HSM_PIN is present in this translation unit; the HMAC output
 * is the only thing an attacker can extract from flash.
 *
 * Power-analysis resistance: wolfcrypt's wc_HmacUpdate feeds the six
 * pin bytes through SHA-256 block compression before any comparison
 * occurs.  The intermediate SHA-256 state words (a–h) are nonlinear
 * combinations of the input; there is no single byte that is simply
 * pin[i] XOR stored[i], removing the direct Hamming-weight oracle.
 */
bool check_pin_cmp(const unsigned char *pin)
{
    uint8_t computed_mac[HMAC_SIZE];
    bool    result;

    if (pin == NULL) { return false; }

    /* HMAC(AUTH_KEY, input_pin, "pin") — domain "pin" prevents cross-use. */
    if (hmac_sha256(AUTH_KEY,
                    pin, PIN_LENGTH,
                    HMAC_DOMAIN_PIN,
                    computed_mac) != 0) {
        secure_zero(computed_mac, sizeof(computed_mac));
        return false;
    }

    /* Constant-time comparison against stored PIN_HMAC. */
    result = secure_compare(computed_mac, PIN_HMAC, HMAC_SIZE);
    secure_zero(computed_mac, sizeof(computed_mac));

    return result;
}

/**
 * Public check_pin: double-pass check_pin_cmp with random_delay between,
 * halt if passes disagree, 5-second penalty on wrong PIN.
 *
 * Commands that use SECURE_PIN_CHECK + manual delay do not call this
 * function; it is retained for callers that need a single-call API.
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

    /* First pass — iterate only provisioned entries. */
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

    /* Second pass. */
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

    if (name == NULL) {
        return false;
    }

    for (i = 0; i < max_len; i++) {
        char c = name[i];

        if (c == '\0') {
            return (i > 0); /* Must have at least one printable character. */
        }

        /* Printable ASCII only: 0x20 (space) through 0x7E (~). */
        if (c < 0x20 || c > 0x7E) {
            return false;
        }
    }

    return false; /* No null terminator within max_len — reject. */
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
