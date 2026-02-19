/**
 * @file HSM.c
 * @brief Boot code and main dispatch loop for the HSM
 * @date 2026
 *
 * Week 4 hardening: removed boot_flag(), obfuscated arrays, crypto_example(),
 * and all debug/verbose error prints from the dispatch loop.
 * All error paths emit only the generic "Operation failed" message via
 * the command handlers themselves.
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

        pkt_len = 0;
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
