/**
 * @file HSM.c
 * @brief Boot code and main dispatch loop for the HSM
 * @date 2026
 *
 * Fix #1 (buffer overflow): pkt_len is now initialised to sizeof(uart_buf)
 * (== MAX_MSG_SIZE) instead of 0.  read_packet() uses it as the hard cap on
 * header.len before calling read_bytes(), so an attacker-supplied length > 
 * MAX_MSG_SIZE is rejected with MSG_BAD_LEN before any bytes are read.
 *
 * Week 4 hardening: boot_flag(), obfuscated arrays, and crypto_example()
 * removed.  All error paths emit only the generic "Operation failed" message.
 *
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

/**********************************************************
 ************************ GLOBALS *************************
 **********************************************************/

/* Single receive buffer.  MAX_MSG_SIZE == sizeof(write_command_t). */
static unsigned char uart_buf[MAX_MSG_SIZE];

/**********************************************************
 ********************* CORE FUNCTIONS *********************
 **********************************************************/

/** @brief Initialize hardware peripherals. */
static void init(void)
{
    SYSCFG_DL_init();
    init_fs();
}

/**********************************************************
 *********************** MAIN LOOP ************************
 **********************************************************/

int main(void)
{
    msg_type_t cmd;
    uint16_t   pkt_len;
    int        result;

    init();

    while (1) {
        STATUS_LED_ON();

        /* FIX #1: pass the true buffer capacity so read_packet() rejects any
         * header.len > MAX_MSG_SIZE before reading any body bytes.
         * Previously this was 0, which disabled the bounds check entirely. */
        pkt_len = (uint16_t)sizeof(uart_buf);
        result  = read_packet(CONTROL_INTERFACE, &cmd, uart_buf, &pkt_len);

        if (result != MSG_OK) {
            STATUS_LED_OFF();
            print_error("Operation failed");
            continue;
        }

        STATUS_LED_OFF();

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
            print_error("Operation failed");
            break;
        }
    }
}
