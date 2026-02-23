/**
 * @file host_messaging.c
 * @brief eCTF Host Messaging Implementation
 * @date 2026
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#include <stdio.h>
#include "host_messaging.h"

/** @brief Read len bytes from UART, ACKing after every 256 bytes.
 *
 *  @return MSG_OK on success, negative on error.
 */
int read_bytes(int uart_id, void *buf, uint16_t len)
{
    int result;
    int i;

    for (i = 0; i < len; i++) {
        if (i % 256 == 0 && i != 0) {
            write_ack(uart_id);
        }
        result = uart_readbyte(uart_id);
        if (result < 0) {
            return result;
        }
        ((uint8_t *)buf)[i] = result;
    }

    return MSG_OK;
}

/** @brief Read a message header from UART.
 *
 *  Discards bytes until MSG_MAGIC ('%') is found, then reads cmd + len.
 */
void read_header(int uart_id, msg_header_t *hdr)
{
    hdr->magic = uart_readbyte(uart_id);
    while (hdr->magic != MSG_MAGIC) {
        hdr->magic = uart_readbyte(uart_id);
    }
    hdr->cmd = uart_readbyte(uart_id);
    read_bytes(uart_id, &hdr->len, sizeof(hdr->len));
}

/** @brief Receive an ACK from UART.
 *
 *  @return MSG_OK on success, MSG_NO_ACK on mismatch.
 */
int read_ack(int uart_id)
{
    msg_header_t ack_buf = {0};
    read_header(uart_id, &ack_buf);
    return (ack_buf.cmd == ACK_MSG) ? MSG_OK : MSG_NO_ACK;
}

/** @brief Write len bytes to UART, expecting ACK after every 256 bytes.
 *
 *  @return MSG_OK on success, else msg_status_t error.
 */
int write_bytes(int uart_id, const void *buf, uint16_t len, bool should_ack)
{
    int i;
    for (i = 0; i < len; i++) {
        if (i % 256 == 0 && i != 0) {
            if (should_ack && read_ack(uart_id) < 0) {
                return MSG_NO_ACK;
            }
        }
        uart_writebyte(uart_id, ((const uint8_t *)buf)[i]);
    }
    fflush(stdout);
    return MSG_OK;
}

/** @brief Write len bytes to UART in hex (2 chars per byte). */
int write_hex(int uart_id, msg_type_t type, const void *buf, size_t len)
{
    msg_header_t hdr;
    int i;
    char hexbuf[128];

    hdr.magic = MSG_MAGIC;
    hdr.cmd   = type;
    hdr.len   = (uint16_t)(len * 2);

    write_bytes(uart_id, &hdr, MSG_HEADER_SIZE, false);
    if (type != DEBUG_MSG && read_ack(uart_id) != MSG_OK) {
        return MSG_NO_ACK;
    }

    for (i = 0; i < (int)len; i++) {
        if (i % (256 / 2) == 0 && i != 0) {
            if (type != DEBUG_MSG && read_ack(uart_id) != MSG_OK) {
                return MSG_NO_ACK;
            }
        }
        snprintf(hexbuf, sizeof(hexbuf), "%02x", ((const uint8_t *)buf)[i]);
        write_bytes(uart_id, hexbuf, 2, false);
    }
    return MSG_OK;
}

/** @brief Send a framed packet to UART, expecting ACK after every 256 bytes.
 *
 *  @return MSG_OK on success, else msg_status_t error.
 */
int write_packet(int uart_id, msg_type_t type, const void *buf, uint16_t len)
{
    msg_header_t hdr;
    int result;

    hdr.magic = MSG_MAGIC;
    hdr.cmd   = type;
    hdr.len   = len;

    result = write_bytes(uart_id, &hdr, MSG_HEADER_SIZE, false);

    if (type == ACK_MSG) {
        return result;
    }

    if (type != DEBUG_MSG && read_ack(uart_id) != MSG_OK) {
        return MSG_NO_ACK;
    }

    if (len > 0) {
        result = write_bytes(uart_id, buf, len, type != DEBUG_MSG);
        if (type != DEBUG_MSG && read_ack(uart_id) != MSG_OK) {
            return MSG_NO_ACK;
        }
    }

    return MSG_OK;
}

/** @brief Read a framed packet from UART into buf.
 *
 *  Fix #1: The length guard `if (*len && header.len > *len)` previously
 *  short-circuited when the caller passed *len == 0, bypassing the bounds
 *  check entirely.  The condition is now `if (header.len > *len)` — it fires
 *  unconditionally whenever len is non-NULL.  All callers must now pass the
 *  actual buffer capacity in *len (never 0 to mean "unlimited").
 *
 *  @param uart_id  UART peripheral index.
 *  @param cmd      Output: opcode of the received packet.
 *  @param buf      Output buffer.  May be NULL if no body is expected.
 *  @param len      In:  capacity of buf (must equal sizeof(buf), not 0).
 *                  Out: actual body length received.
 *  @return MSG_OK on success, else msg_status_t error.
 */
int read_packet(int uart_id, msg_type_t *cmd, void *buf, uint16_t *len)
{
    msg_header_t header = {0};

    if (cmd == NULL) {
        return MSG_BAD_PTR;
    }

    read_header(uart_id, &header);
    *cmd = header.cmd;

    if (len != NULL) {
        /* FIX #1: removed "*len &&" — guard fires for every non-NULL len,
         * including the case the caller passes the buffer size directly.
         * Any header.len larger than the caller's buffer is rejected. */
        if (header.len > *len) {
            *len = 0;
            return MSG_BAD_LEN;
        }
        *len = header.len;
    }

    if (header.cmd != ACK_MSG) {
        write_ack(uart_id);
        if (header.len && buf != NULL) {
            if (read_bytes(uart_id, buf, header.len) != MSG_OK) {
                return MSG_NO_ACK;
            }
        }
        if (header.len) {
            if (write_ack(uart_id) != MSG_OK) {
                return MSG_NO_ACK;
            }
        }
    }

    return MSG_OK;
}
