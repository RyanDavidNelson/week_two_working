/**
 * @file "simple_uart.c"
 * @author Samuel Meyers
 * @brief UART Interrupt Handler Implementation
 * @date 2026
 *
 * This source file is part of an example system for MITRE's 2026 Embedded CTF (eCTF).
 * This code is being provided only for educational purposes for the 2026 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#include "simple_uart.h"

/**********************************************************
 *************** HARDWARE ABSTRACTIONS ********************
 **********************************************************/

/* UART peripheral handles indexed by uart_id. */
UART_Regs *uart_inst[] = {UART_0_INST, UART_1_INST};

UART_Regs *get_uart_handle(int uart_id) {
    if (uart_id < 0 || uart_id > CONFIG_UART_COUNT) {
        /* Default on bad input is CONTROL_INTERFACE. */
        return uart_inst[0];
    }
    return uart_inst[uart_id];
}

/** @brief Reads the next available character from UART, blocking indefinitely.
 *
 *  @param uart_id The index of UART to use.
 *  @return The byte read as an unsigned int.
 */
int uart_readbyte(int uart_id) {
    uint8_t data = DL_UART_receiveDataBlocking(get_uart_handle(uart_id));
    return data;
}

/** @brief Reads the next available character from UART with a bounded timeout.
 *
 *  Polls DL_UART_isRXFIFOEmpty in a counted loop so the caller cannot hang
 *  forever if the peer stalls or the wire is disconnected.
 *
 *  Loop counter waited in [0, UART_TRANSFER_TIMEOUT_CYCLES);
 *  terminates when a byte arrives or the limit is reached.
 *
 *  @param uart_id   The index of UART to use.
 *  @param out_byte  Written with the received byte on success.
 *  @return 0 on success, -1 on timeout.
 */
int uart_readbyte_timeout(int uart_id, int *out_byte) {
    UART_Regs *uart   = get_uart_handle(uart_id);
    uint32_t   waited;

    for (waited = 0; waited < UART_TRANSFER_TIMEOUT_CYCLES; waited++) {
        if (!DL_UART_isRXFIFOEmpty(uart)) {
            *out_byte = (int)DL_UART_receiveData(uart);
            return 0;
        }
    }
    return -1; /* timeout */
}

/** @brief Writes a byte to UART.
 *
 *  @param uart_id The index of UART to use.
 *  @param data The byte to be written.
 */
void uart_writebyte(int uart_id, uint8_t data) {
    DL_UART_transmitDataBlocking(get_uart_handle(uart_id), data);
}

/** @brief Discard any bytes currently in the UART RX FIFO (no blocking wait).
 *
 *  Reads and discards up to max_bytes bytes that are immediately available.
 *  Returns as soon as the FIFO is empty without waiting for new data.
 *  Loop counter drain_i in [0, max_bytes); terminates on empty FIFO.
 *
 *  @param uart_id   UART to drain.
 *  @param max_bytes Upper bound on bytes to discard.
 *  @return Number of bytes discarded.
 */
uint8_t uart_drain_rx(int uart_id, uint8_t max_bytes) {
    UART_Regs *uart    = get_uart_handle(uart_id);
    uint8_t    drain_i;

    /* Discard bytes present in FIFO right now; do NOT wait for new ones.
     * Loop counter drain_i in [0, max_bytes); terminates when FIFO is empty. */
    for (drain_i = 0; drain_i < max_bytes; drain_i++) {
        if (DL_UART_isRXFIFOEmpty(uart)) {
            break; /* nothing left */
        }
        (void)DL_UART_receiveData(uart);
    }
    return drain_i;
}
