/**
 * @file HSM.c
 * @brief Boot code and main function for the HSM
 * @date 2026
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#include <stdint.h>
#include <string.h>

#include "simple_flash.h"
#include "host_messaging.h"
#include "commands.h"
#include "filesystem.h"
#include "ti_msp_dl_config.h"
#include "status_led.h"
#include "simple_uart.h"
#include "security.h"

/*
 * Single receive buffer for all host commands.
 * Sized to the largest possible host→HSM packet (write_command_t = 8251 B).
 */
static unsigned char uart_buf[MAX_MSG_SIZE];

/**
 * @brief Initialize peripherals for system boot
 */
void init(void)
{
    SYSCFG_DL_init();
    init_fs();

    /* TRNG is required for security functions */
    int trng_result = trng_init();
    if (trng_result != 0) {
        /* Halt with error blink pattern */
        while (1) {
            for (int i = 0; i < (-trng_result); i++) {
                STATUS_LED_ON();
                delay_ms(100);
                STATUS_LED_OFF();
                delay_ms(100);
            }
            delay_ms(500);
        }
    }

    /*
     * Seed the stack canary from TRNG.
     *
     * Must happen after trng_init() and before any instrumented function
     * returns.  All command handlers run inside the main() while(1) loop
     * which starts after init() returns — no instrumented function has
     * returned yet at this point, so the window of zero-canary exposure
     * is exactly the startup code before this line.
     *
     * Canary format (little-endian Cortex-M0+):
     *   byte 0 (lowest address, hit first by upward smash) = 0x00
     *   bytes 1-3 = random TRNG bytes
     *
     * Masking off the low byte embeds a null terminator at byte 0.
     * A string-copy overwrite that produces any non-zero value at byte 0
     * corrupts the canary before reaching the saved return address.
     * The 24 random bits in bytes 1-3 defeat non-string overwrites.
     */
    uint32_t raw_canary = trng_read_word();
    __stack_chk_guard   = raw_canary & 0xFFFFFF00U;
}

int main(void)
{
    msg_type_t cmd;
    int        result;
    uint16_t   pkt_len;

    init();

    /* Main command processing loop */
    while (1) {
        STATUS_LED_ON();

        /*
         * read_packet() only enforces the overflow guard when *len != 0:
         *   if (*len != 0 && header.len > *len) { return MSG_BAD_LEN; }
         * Passing 0 disabled the check, allowing an attacker to send a
         * packet with header.len up to UINT16_MAX (65535) and write past
         * the end of uart_buf[8251] into adjacent .bss (s_work, FAT).
         * Passing MAX_MSG_SIZE caps any inbound packet at the buffer size.
         */
        pkt_len = MAX_MSG_SIZE;
        result  = read_packet(CONTROL_INTERFACE, &cmd, uart_buf, &pkt_len);

        if (result != MSG_OK) {
            STATUS_LED_OFF();
            continue;
        }

        STATUS_LED_OFF();

        /* Dispatch the requested command */
        switch (cmd) {
        case LIST_MSG:
            list(pkt_len, uart_buf);
            break;

        case READ_MSG:
            read(pkt_len, uart_buf);
            break;

        case WRITE_MSG:
            write(pkt_len, uart_buf);
            break;

        case RECEIVE_MSG:
            receive(pkt_len, uart_buf);
            break;

        case INTERROGATE_MSG:
            interrogate(pkt_len, uart_buf);
            break;

        case LISTEN_MSG:
            listen(pkt_len, uart_buf);
            break;

        default:
            break;
        }
    }
}
