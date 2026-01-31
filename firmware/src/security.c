/**
 * @file security.c
 * @brief Security primitives implementation for eCTF HSM
 * @date 2026
 *
 * TRNG implementation based on TI SDK TRNG.Board.c.xdt template
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#include "security.h"
#include "secrets.h"
#include "filesystem.h"
#include "host_messaging.h"
#include "ti_msp_dl_config.h"
#include <ti/driverlib/dl_trng.h>
#include <ti/devices/msp/msp.h>
#include <stdio.h>

/* Calibrated value - adjust based on hardware testing */
#ifndef CYCLES_PER_MS
#define CYCLES_PER_MS 32000
#endif

/* Debug output buffer */
static char dbg_buf[128];

/*
 * Delay function - copied from TI SDK dl_common.c
 * This ensures we don't depend on external linking of dl_common.c
 */
static void trng_delay_cycles(uint32_t cycles)
{
    /* this is a scratch register for the compiler to use */
    uint32_t scratch;
    /* There will be a 2 cycle delay here to fetch & decode instructions
     * if branch and linking to this function */
    /* Subtract 2 net cycles for constant offset: +2 cycles for entry jump,
     * +2 cycles for exit, -1 cycle for a shorter loop cycle on the last loop,
     * -1 for this instruction */
    __asm volatile(
#ifdef __GNUC__
        ".syntax unified\n\t"
#endif
        "SUBS %0, %[numCycles], #2; \n"
        "%=: \n\t"
        "SUBS %0, %0, #4; \n\t"
        "NOP; \n\t"
        "BHS  %=b;" /* branches back to the label defined above if number > 0 */
        /* Return: 2 cycles */
        : "=&r"(scratch)
        : [ numCycles ] "r"(cycles));
}

/*
 * Hardware TRNG Functions - Based on TI SDK template
 */

int trng_init(void) {
    print_debug("TRNG: Init (TI SDK method)...\n");
    
    /* Step 1: Enable power to TRNG */
    print_debug("TRNG: Enabling power...\n");
    DL_TRNG_enablePower(TRNG);
    
    /* Wait for power stabilization
     * POWER_STARTUP_DELAY is typically defined by SysConfig
     * Default to 32000 cycles (~1ms at 32MHz) if not defined
     */
#ifdef POWER_STARTUP_DELAY
    trng_delay_cycles(POWER_STARTUP_DELAY);
#else
    trng_delay_cycles(32000);
#endif
    print_debug("TRNG: Power stabilized\n");
    
    /* Step 2: Set clock divider FIRST (before any commands)
     * 32MHz / 2 = 16MHz - TRNG requires specific clock frequency
     */
    print_debug("TRNG: Setting clock divider...\n");
    DL_TRNG_setClockDivider(TRNG, DL_TRNG_CLOCK_DIVIDE_2);
    
    /* Step 3: Run digital block start-up self-test */
    print_debug("TRNG: Running digital self-test...\n");
    DL_TRNG_sendCommand(TRNG, DL_TRNG_CMD_TEST_DIG);
    while (!DL_TRNG_isCommandDone(TRNG))
        ;
    DL_TRNG_clearInterruptStatus(TRNG, DL_TRNG_INTERRUPT_CMD_DONE_EVENT);
    
    /* CRITICAL: Must delay ~100000 cycles before reading TEST_RESULTS 
     * This is documented in TI SDK template! */
    print_debug("TRNG: Waiting before reading digital test result...\n");
    trng_delay_cycles(100000);
    
    uint8_t dig_result = DL_TRNG_getDigitalHealthTestResults(TRNG);
    sprintf(dbg_buf, "TRNG: Digital test result: 0x%02X (want 0xFF)\n", dig_result);
    print_debug(dbg_buf);
    if (dig_result != DL_TRNG_DIGITAL_HEALTH_TEST_SUCCESS) {
        print_error("TRNG: Digital test FAILED!\n");
        return -1;
    }
    print_debug("TRNG: Digital test PASSED\n");
    
    /* Step 4: Run analog block start-up self-test */
    print_debug("TRNG: Running analog self-test...\n");
    DL_TRNG_sendCommand(TRNG, DL_TRNG_CMD_TEST_ANA);
    while (!DL_TRNG_isCommandDone(TRNG))
        ;
    DL_TRNG_clearInterruptStatus(TRNG, DL_TRNG_INTERRUPT_CMD_DONE_EVENT);
    
    /* CRITICAL: Must delay ~100000 cycles before reading TEST_RESULTS */
    print_debug("TRNG: Waiting before reading analog test result...\n");
    trng_delay_cycles(100000);
    
    uint8_t ana_result = DL_TRNG_getAnalogHealthTestResults(TRNG);
    sprintf(dbg_buf, "TRNG: Analog test result: 0x%02X (want 0x01)\n", ana_result);
    print_debug(dbg_buf);
    if (ana_result != DL_TRNG_ANALOG_HEALTH_TEST_SUCCESS) {
        print_error("TRNG: Analog test FAILED!\n");
        return -2;
    }
    print_debug("TRNG: Analog test PASSED\n");
    
    /* Step 5: Enter normal function mode
     * TRNG doesn't automatically transition to NORM_FUNC after health tests
     */
    print_debug("TRNG: Entering NORM_FUNC mode...\n");
    DL_TRNG_sendCommand(TRNG, DL_TRNG_CMD_NORM_FUNC);
    while (!DL_TRNG_isCommandDone(TRNG))
        ;
    DL_TRNG_clearInterruptStatus(TRNG, DL_TRNG_INTERRUPT_CMD_DONE_EVENT);
    
    /* Step 6: Set decimation rate AFTER entering NORM_FUNC */
    DL_TRNG_setDecimationRate(TRNG, DL_TRNG_DECIMATION_RATE_4);
    
    print_debug("TRNG: Init complete!\n");
    return 0;
}

uint32_t trng_read_word(void) {
    /* Wait for capture to be ready */
    while (!DL_TRNG_isCaptureReady(TRNG))
        ;
    
    /* Read the random value */
    uint32_t value = DL_TRNG_getCapture(TRNG);
    
    /* Clear the capture ready flag */
    DL_TRNG_clearInterruptStatus(TRNG, DL_TRNG_INTERRUPT_CAPTURE_RDY_EVENT);
    
    /* 
     * Trigger the next capture for subsequent reads.
     * TRNG does NOT auto-generate - each capture must be explicitly triggered.
     */
    DL_TRNG_sendCommand(TRNG, DL_TRNG_CMD_NORM_FUNC);
    
    return value;
}

uint8_t trng_read_byte(void) {
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

int trng_fill_buffer(uint8_t *buf, size_t len) {
    if (buf == NULL || len == 0) {
        return -1;
    }
    
    size_t i = 0;
    
    /* Fill with full words where possible */
    while (i + 4 <= len) {
        uint32_t word = trng_read_word();
        buf[i++] = (uint8_t)(word & 0xFF);
        buf[i++] = (uint8_t)((word >> 8) & 0xFF);
        buf[i++] = (uint8_t)((word >> 16) & 0xFF);
        buf[i++] = (uint8_t)((word >> 24) & 0xFF);
    }
    
    /* Fill remaining bytes */
    while (i < len) {
        buf[i++] = trng_read_byte();
    }
    
    return 0;
}

/*
 * Core Security Functions
 */

bool secure_compare(const void *a, const void *b, size_t len) {
    const volatile uint8_t *pa = (const volatile uint8_t *)a;
    const volatile uint8_t *pb = (const volatile uint8_t *)b;
    volatile uint8_t result = 0;
    
    for (size_t i = 0; i < len; i++) {
        const uint8_t byte_a = pa[i];
        const uint8_t byte_b = pb[i];
        result |= byte_a ^ byte_b;
    }
    
    return (result == 0);
}

bool check_pin(unsigned char *pin) {
    volatile uint8_t result1 = 0;
    volatile uint8_t result2 = 0;
    
    /* First comparison pass */
    for (int i = 0; i < PIN_LENGTH; i++) {
        result1 |= pin[i] ^ HSM_PIN[i];
    }
    
    /* Random delay between checks (0-127 iterations) */
    const uint8_t delay_max = trng_read_byte() & 0x7F;
    for (volatile uint8_t d = 0; d < delay_max; d++) {
        __asm volatile ("nop");
    }
    
    /* Second comparison pass */
    for (int j = 0; j < PIN_LENGTH; j++) {
        result2 |= pin[j] ^ HSM_PIN[j];
    }
    
    /* Glitch detection - if results differ, halt */
    if (result1 != result2) {
        while (1) {
            __asm volatile ("nop");
        }
    }
    
    /* Wrong PIN: 5-second delay to rate-limit brute force */
    if (result1 != 0) {
        busy_wait_ms(5000);
        return false;
    }
    
    return true;
}

bool validate_permission(uint16_t group_id, permission_enum_t perm) {
    volatile bool found_pass1 = false;
    volatile bool found_pass2 = false;
    
    /* First pass */
    for (int i = 0; i < MAX_PERMS; i++) {
        const uint16_t entry_group = global_permissions[i].group_id;
        const bool group_match = (entry_group == group_id);
        
        bool has_perm = false;
        switch (perm) {
            case PERM_READ:    has_perm = global_permissions[i].read; break;
            case PERM_WRITE:   has_perm = global_permissions[i].write; break;
            case PERM_RECEIVE: has_perm = global_permissions[i].receive; break;
            default:           has_perm = false; break;
        }
        
        if (group_match && has_perm) {
            found_pass1 = true;
        }
    }
    
    /* Random delay */
    const uint8_t delay_max = trng_read_byte() & 0x7F;
    for (volatile uint8_t d = 0; d < delay_max; d++) {
        __asm volatile ("nop");
    }
    
    /* Second pass */
    for (int j = 0; j < MAX_PERMS; j++) {
        const uint16_t entry_group = global_permissions[j].group_id;
        const bool group_match = (entry_group == group_id);
        
        bool has_perm = false;
        switch (perm) {
            case PERM_READ:    has_perm = global_permissions[j].read; break;
            case PERM_WRITE:   has_perm = global_permissions[j].write; break;
            case PERM_RECEIVE: has_perm = global_permissions[j].receive; break;
            default:           has_perm = false; break;
        }
        
        if (group_match && has_perm) {
            found_pass2 = true;
        }
    }
    
    /* Glitch detection */
    if (found_pass1 != found_pass2) {
        while (1) {
            __asm volatile ("nop");
        }
    }
    
    return found_pass1;
}

/*
 * Input Validation Functions
 */

bool validate_slot(uint8_t slot) {
    return (slot < MAX_FILE_COUNT);
}

bool validate_name(const char *name, size_t max_len) {
    if (name == NULL) {
        return false;
    }
    
    for (size_t i = 0; i < max_len; i++) {
        const char c = name[i];
        
        if (c == '\0') {
            return (i > 0);  /* Must have at least one character */
        }
        
        /* Only allow printable ASCII (0x20-0x7E) */
        if (c < 0x20 || c > 0x7E) {
            return false;
        }
    }
    
    /* No null terminator found within max_len */
    return false;
}

bool validate_perm_count(uint8_t count) {
    return (count <= MAX_PERMS);
}

bool validate_contents_len(uint16_t len) {
    return (len <= MAX_CONTENTS_SIZE);
}

bool validate_bool(uint8_t value) {
    return (value == 0 || value == 1);
}

/*
 * Memory Safety Functions
 */

void explicit_bzero(void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    
    for (size_t i = 0; i < len; i++) {
        p[i] = 0;
    }
    
    /* Memory barrier to prevent optimization */
    __asm volatile ("" ::: "memory");
}

void busy_wait_ms(uint32_t ms) {
    const uint32_t total_cycles = ms * CYCLES_PER_MS;
    
    for (volatile uint32_t i = 0; i < total_cycles; i++) {
        __asm volatile ("nop");
    }
}
