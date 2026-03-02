/**
 * @file "simple_uart.h"
 * @author Samuel Meyers
 * @brief Simple UART Interface Header
 * @date 2026
 *
 * This source file is part of an example system for MITRE's 2026 Embedded CTF (eCTF).
 * This code is being provided only for educational purposes for the 2026 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#ifndef __SIMPLE_UART__
#define __SIMPLE_UART__

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "host_messaging.h"

#include <ti/devices/msp/msp.h>
#include <ti/driverlib/dl_gpio.h>
#include "ti_msp_dl_config.h"

/******************************** MACRO DEFINITIONS ********************************/
#define UART_BAUD            115200
#define CONTROL_INTERFACE    0
#define TRANSFER_INTERFACE   1

#define CONFIG_UART_COUNT    2

/*
 * Per-byte timeout for TRANSFER_INTERFACE reads.
 *
 * The listen board must complete all crypto (HMAC verifications, flash reads,
 * perm checks, resp_auth) before sending its first byte of R2/R4.  Without
 * random_delay() calls that processing takes ~50 ms worst case; flash reads
 * can add another ~50 ms.  Setting the timeout to ~3 seconds gives ample
 * margin without approaching the 5-second host-side operation deadline.
 *
 * At 32 MHz with ~9-10 cycles per loop body:
 *   9,600,000 iterations × 10 cycles / 32,000,000 Hz ≈ 3 seconds
 *
 * Only used on TRANSFER_INTERFACE; CONTROL_INTERFACE blocks indefinitely.
 */
#define UART_TRANSFER_TIMEOUT_CYCLES  9600000U

/******************************** FUNCTION PROTOTYPES ******************************/

/** @brief Reads the next available character from UART, blocking indefinitely.
 *
 *  @param uart_id The index of UART to use.
 *  @return The byte read as an unsigned int.
 */
int uart_readbyte(int uart_id);

/** @brief Reads the next available character from UART with a bounded timeout.
 *
 *  Polls DL_UART_isRXFIFOEmpty in a counted loop so the caller cannot hang
 *  forever when the peer stalls or the wire is disconnected.
 *  Only intended for TRANSFER_INTERFACE; CONTROL_INTERFACE should use
 *  uart_readbyte() which blocks until the host delivers data.
 *  terminates when a byte arrives or the limit is reached.
 *
 *  @param uart_id   The index of UART to use.
 *  @param out_byte  Written with the received byte on success.
 *  @return 0 on success, -1 on timeout.
 */
int uart_readbyte_timeout(int uart_id, int *out_byte);

/** @brief Writes a byte to UART.
 *
 *  @param uart_id The index of UART to use.
 *  @param data The byte to be written.
 */
void uart_writebyte(int uart_id, uint8_t data);

/** @brief Discard any bytes currently in the UART RX FIFO (no blocking wait).
 *
 *  Reads and discards up to max_bytes bytes that are immediately available.
 *  Returns as soon as the FIFO is empty without waiting for new data.
 *  @param uart_id   UART to drain.
 *  @param max_bytes Upper bound on bytes to discard.
 *  @return Number of bytes discarded.
 */
uint8_t uart_drain_rx(int uart_id, uint8_t max_bytes);

#endif // __SIMPLE_UART__
