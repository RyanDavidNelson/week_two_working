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
         * FIX #1: initialise pkt_len to MAX_MSG_SIZE, not 0.
         *
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
