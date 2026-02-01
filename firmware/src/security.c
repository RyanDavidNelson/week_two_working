/**
 * @file security.c
 * @brief Security primitives implementation for eCTF HSM
 * @date 2026
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#include "security.h"
#include "secrets.h"
#include "filesystem.h"
#include "ti_msp_dl_config.h"
#include <ti/driverlib/dl_trng.h>
#include <ti/devices/msp/msp.h>

/*
 * Timing Functions
 */

void delay_cycles(uint32_t cycles)
{
    /* Assembly delay from TI SDK dl_common.c - cycle-accurate timing */
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
    /* Split into 100ms chunks to avoid uint32_t overflow for large delays */
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
    /* Random delay 0 to ~4ms for glitch resistance */
    uint32_t delay = (trng_read_byte() & 0x7F) * (CYCLES_PER_MS / 8);
    delay_cycles(delay);
}

/*
 * Hardware TRNG Functions
 */

int trng_init(void)
{
    /* Enable power and wait for stabilization */
    DL_TRNG_enablePower(TRNG);
#ifdef POWER_STARTUP_DELAY
    delay_cycles(POWER_STARTUP_DELAY);
#else
    delay_cycles(32000);
#endif

    /* Set clock divider (32MHz / 2 = 16MHz for TRNG) */
    DL_TRNG_setClockDivider(TRNG, DL_TRNG_CLOCK_DIVIDE_2);

    /* Digital self-test */
    DL_TRNG_sendCommand(TRNG, DL_TRNG_CMD_TEST_DIG);
    while (!DL_TRNG_isCommandDone(TRNG))
        ;
    DL_TRNG_clearInterruptStatus(TRNG, DL_TRNG_INTERRUPT_CMD_DONE_EVENT);

    /* Must delay before reading test results (per TI documentation) */
    delay_cycles(100000);

    if (DL_TRNG_getDigitalHealthTestResults(TRNG) != DL_TRNG_DIGITAL_HEALTH_TEST_SUCCESS) {
        return -1;
    }

    /* Analog self-test */
    DL_TRNG_sendCommand(TRNG, DL_TRNG_CMD_TEST_ANA);
    while (!DL_TRNG_isCommandDone(TRNG))
        ;
    DL_TRNG_clearInterruptStatus(TRNG, DL_TRNG_INTERRUPT_CMD_DONE_EVENT);

    delay_cycles(100000);

    if (DL_TRNG_getAnalogHealthTestResults(TRNG) != DL_TRNG_ANALOG_HEALTH_TEST_SUCCESS) {
        return -2;
    }

    /* Enter normal operation mode */
    DL_TRNG_sendCommand(TRNG, DL_TRNG_CMD_NORM_FUNC);
    while (!DL_TRNG_isCommandDone(TRNG))
        ;
    DL_TRNG_clearInterruptStatus(TRNG, DL_TRNG_INTERRUPT_CMD_DONE_EVENT);

    DL_TRNG_setDecimationRate(TRNG, DL_TRNG_DECIMATION_RATE_4);

    return 0;
}

uint32_t trng_read_word(void)
{
    /* Wait for capture to be ready */
    while (!DL_TRNG_isCaptureReady(TRNG))
        ;

    uint32_t value = DL_TRNG_getCapture(TRNG);
    DL_TRNG_clearInterruptStatus(TRNG, DL_TRNG_INTERRUPT_CAPTURE_RDY_EVENT);

    /* Trigger next capture (TRNG doesn't auto-generate) */
    DL_TRNG_sendCommand(TRNG, DL_TRNG_CMD_NORM_FUNC);

    return value;
}

uint8_t trng_read_byte(void)
{
    static uint32_t cached_word = 0;
    static uint8_t bytes_remaining = 0;

    if (bytes_remaining == 0) {
        cached_word = trng_read_word();
        bytes_remaining = 4;
    }

    uint8_t result = (uint8_t)(cached_word & 0xFF);
    cached_word >>= 8;
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

    for (size_t i = 0; i < len; i++) {
        result |= pa[i] ^ pb[i];
    }

    return (result == 0);
}

bool check_pin(unsigned char *pin)
{
    volatile uint8_t result1 = 0;
    volatile uint8_t result2 = 0;

    /* First comparison pass */
    for (int i = 0; i < PIN_LENGTH; i++) {
        result1 |= pin[i] ^ HSM_PIN[i];
    }

    /* Random delay between checks for glitch resistance */
    random_delay();

    /* Second comparison pass */
    for (int j = 0; j < PIN_LENGTH; j++) {
        result2 |= pin[j] ^ HSM_PIN[j];
    }

    /* Glitch detection: halt if results differ */
    if (result1 != result2) {
        while (1) {
            __asm volatile("nop");
        }
    }

    /* Rate-limit brute force with 5-second delay on wrong PIN */
    if (result1 != 0) {
        delay_ms(5000);
        return false;
    }

    return true;
}

bool validate_permission(uint16_t group_id, permission_enum_t perm)
{
    volatile bool found_pass1 = false;
    volatile bool found_pass2 = false;

    /* First pass */
    for (int i = 0; i < MAX_PERMS; i++) {
        bool group_match = (global_permissions[i].group_id == group_id);
        bool has_perm = false;

        switch (perm) {
        case PERM_READ:
            has_perm = global_permissions[i].read;
            break;
        case PERM_WRITE:
            has_perm = global_permissions[i].write;
            break;
        case PERM_RECEIVE:
            has_perm = global_permissions[i].receive;
            break;
        default:
            break;
        }

        if (group_match && has_perm) {
            found_pass1 = true;
        }
    }

    /* Random delay for glitch resistance */
    random_delay();

    /* Second pass */
    for (int j = 0; j < MAX_PERMS; j++) {
        bool group_match = (global_permissions[j].group_id == group_id);
        bool has_perm = false;

        switch (perm) {
        case PERM_READ:
            has_perm = global_permissions[j].read;
            break;
        case PERM_WRITE:
            has_perm = global_permissions[j].write;
            break;
        case PERM_RECEIVE:
            has_perm = global_permissions[j].receive;
            break;
        default:
            break;
        }

        if (group_match && has_perm) {
            found_pass2 = true;
        }
    }

    /* Glitch detection */
    if (found_pass1 != found_pass2) {
        while (1) {
            __asm volatile("nop");
        }
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
    if (name == NULL) {
        return false;
    }

    for (size_t i = 0; i < max_len; i++) {
        char c = name[i];

        if (c == '\0') {
            return (i > 0); /* Must have at least one character */
        }

        /* Only allow printable ASCII (0x20-0x7E) */
        if (c < 0x20 || c > 0x7E) {
            return false;
        }
    }

    return false; /* No null terminator found */
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
