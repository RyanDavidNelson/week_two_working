/**
 * @file simple_uart.c
 * @brief UART Driver Implementation
 * @date 2026
 *
 * Week 4: uart_readbyte() polls with a 2000ms per-byte timeout.
 * Uses delay_ms() from security.h (which calls delay_cycles()) instead of
 * a duplicate busy-wait implementation, so timing is consistent with all
 * other security-critical delays in the firmware.
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#include "simple_uart.h"
#include "security.h"   /* delay_ms(), CYCLES_PER_MS */

/**********************************************************
 *************** CONFIGURATION ****************************
 **********************************************************/

/* Maximum time to wait for a single byte, in milliseconds */
#define UART_TIMEOUT_MS  2000UL

/**********************************************************
 *************** HARDWARE ABSTRACTIONS ********************
 **********************************************************/

/* Peripheral handles for the two UART instances */
static UART_Regs *uart_inst[] = { UART_0_INST, UART_1_INST };

static UART_Regs *get_uart_handle(int uart_id)
{
    if (uart_id < 0 || uart_id >= CONFIG_UART_COUNT) {
        return uart_inst[0]; /* safe default on bad index */
    }
    return uart_inst[uart_id];
}

/**
 * @brief Read one byte from UART with a 2000ms timeout.
 *
 * Polls DL_UART_isRXFIFOEmpty() in 1ms steps using delay_ms() from
 * security.c, which is the same calibrated busy-wait used for PIN delays
 * and random delays.  Returns -1 on timeout so the protocol layer can
 * return a clean error instead of hanging indefinitely.
 *
 * @param uart_id  Index of UART peripheral (0 = CONTROL, 1 = TRANSFER).
 * @return         Byte value 0-255 on success, -1 on timeout.
 */
int uart_readbyte(int uart_id)
{
    UART_Regs *uart = get_uart_handle(uart_id);
    uint32_t elapsed_ms = 0;

    /* Poll in 1ms increments using the shared delay primitive */
    while (DL_UART_isRXFIFOEmpty(uart)) {
        delay_ms(1);
        elapsed_ms++;
        if (elapsed_ms >= UART_TIMEOUT_MS) {
            return -1; /* timeout */
        }
    }

    return (int)DL_UART_receiveData(uart);
}

/**
 * @brief Write one byte to UART (blocking transmit).
 *
 * @param uart_id  Index of UART peripheral.
 * @param data     Byte to transmit.
 */
void uart_writebyte(int uart_id, uint8_t data)
{
    DL_UART_transmitDataBlocking(get_uart_handle(uart_id), data);
}
