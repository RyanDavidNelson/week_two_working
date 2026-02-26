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
 * Approximate iteration count for a ~1 second timeout on TRANSFER_INTERFACE.
 * DL_UART_isRXFIFOEmpty polls the UART RX FIFO status register.
 * At 32 MHz with ~9-10 cycles per loop body, 3,200,000 iterations ≈ 1 s.
 * Used only on TRANSFER_INTERFACE; CONTROL_INTERFACE blocks indefinitely.
 */
#define UART_TRANSFER_TIMEOUT_CYCLES  3200000U

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
 *
 *  Loop counter waited in [0, UART_TRANSFER_TIMEOUT_CYCLES);
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

#endif // __SIMPLE_UART__
