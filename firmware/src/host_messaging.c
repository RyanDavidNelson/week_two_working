/**
 * @file host_messaging.c
 * @author Samuel Meyers
 * @brief eCTF Host Messaging Implementation
 * @date 2026
 *
 * This source file is part of an example system for MITRE's 2026 Embedded CTF (eCTF).
 * This code is being provided only for educational purposes for the 2026 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#include <stdio.h>
#include "host_messaging.h"

/**********************************************************
 ****************** INTERNAL HELPERS **********************
 **********************************************************/

/*
 * Read one byte from uart_id, respecting the interface type:
 *   CONTROL_INTERFACE  — blocks indefinitely (host always eventually sends).
 *   TRANSFER_INTERFACE — uses uart_readbyte_timeout; returns MSG_TIMEOUT if
 *                        the peer does not send a byte within the timeout window.
 *
 * Returns MSG_OK and writes *byte_out on success, MSG_TIMEOUT on timeout.
 */
static int uart_read_guarded(int uart_id, uint8_t *byte_out) {
    if (uart_id == TRANSFER_INTERFACE) {
        int tmp;
        if (uart_readbyte_timeout(uart_id, &tmp) != 0) {
            return MSG_TIMEOUT;
        }
        *byte_out = (uint8_t)tmp;
        return MSG_OK;
    }
    *byte_out = (uint8_t)uart_readbyte(uart_id);
    return MSG_OK;
}

/**********************************************************
 ****************** INTERNAL READ HELPERS *****************
 **********************************************************/

/** @brief Read len bytes from UART, ACKing after every 256 bytes.
 *
 *  On TRANSFER_INTERFACE each byte read is timeout-guarded; returns
 *  MSG_TIMEOUT immediately if any byte does not arrive in time.
 *
 *  @param uart_id The id of the uart to read from.
 *  @param buf     Buffer to store incoming bytes.
 *  @param len     Number of bytes to read.
 *  @return MSG_OK on success, MSG_TIMEOUT on peer timeout, negative on error.
 */
int read_bytes(int uart_id, void *buf, uint16_t len) {
    uint16_t i;
    uint8_t  byte_val;
    int      result;

    for (i = 0; i < len; i++) {
        if (i % 256 == 0 && i != 0) { /* ACK after every 256 bytes received. */
            write_ack(uart_id);
        }
        result = uart_read_guarded(uart_id, &byte_val);
        if (result != MSG_OK) {
            return result; /* propagate MSG_TIMEOUT or error */
        }
        ((uint8_t *)buf)[i] = byte_val;
    }
    return MSG_OK;
}

/** @brief Read a message header from UART.
 *
 *  Discards bytes until MSG_MAGIC is found (framing sync), then reads the
 *  opcode and 2-byte length.  On TRANSFER_INTERFACE each read is timeout-
 *  guarded and the sync loop is capped at MAX_SYNC_DISCARD bytes.
 *
 *  @param uart_id The id of the uart to read from.
 *  @param hdr     Buffer to store the parsed header.
 *  @return MSG_OK on success, MSG_TIMEOUT if the peer stalled.
 */
static int read_header(int uart_id, msg_header_t *hdr) {
    uint8_t  magic_byte;
    uint8_t  discard_count; /* loop counter in [0, MAX_SYNC_DISCARD) */
    int      result;

    /* Read first byte. */
    result = uart_read_guarded(uart_id, &magic_byte);
    if (result != MSG_OK) {
        return result;
    }

    /*
     * Sync loop: discard bytes until MSG_MAGIC is found.
     * Counter discard_count in [0, MAX_SYNC_DISCARD); terminates when
     * the magic byte is found or the discard limit is reached.
     */
    for (discard_count = 0;
         magic_byte != MSG_MAGIC && discard_count < MAX_SYNC_DISCARD;
         discard_count++) {
        result = uart_read_guarded(uart_id, &magic_byte);
        if (result != MSG_OK) {
            return result;
        }
    }

    if (magic_byte != MSG_MAGIC) {
        return MSG_TIMEOUT; /* exceeded sync limit without finding framing */
    }

    hdr->magic = (char)magic_byte;

    /* Read opcode byte. */
    result = uart_read_guarded(uart_id, (uint8_t *)&hdr->cmd);
    if (result != MSG_OK) {
        return result;
    }

    /* Read 2-byte little-endian length field. */
    return read_bytes(uart_id, &hdr->len, sizeof(hdr->len));
}

/** @brief Receive an ACK from UART.
 *
 *  @param uart_id The id of the uart to read from.
 *  @return MSG_OK on success, MSG_NO_ACK if wrong opcode, MSG_TIMEOUT on peer timeout.
 */
int read_ack(int uart_id) {
    msg_header_t ack_buf = {0};
    int          result;

    result = read_header(uart_id, &ack_buf);
    if (result != MSG_OK) {
        return result;
    }
    return (ack_buf.cmd == ACK_MSG) ? MSG_OK : MSG_NO_ACK;
}

/**********************************************************
 ****************** WRITE FUNCTIONS ***********************
 **********************************************************/

/** @brief Write len bytes to UART, expecting an ACK after every 256 bytes.
 *
 *  @param uart_id    The id of the uart to write to.
 *  @param buf        Buffer containing bytes to send.
 *  @param len        Number of bytes to send.
 *  @param should_ack True if ACKs are expected between 256-byte blocks.
 *  @return MSG_OK on success, else other msg_status_t.
 */
int write_bytes(int uart_id, const void *buf, uint16_t len, bool should_ack) {
    uint16_t i;

    for (i = 0; i < len; i++) {
        if (i % 256 == 0 && i != 0) { /* Expect an ACK after every 256 bytes sent. */
            if (should_ack && read_ack(uart_id) < 0) {
                return MSG_NO_ACK;
            }
        }
        uart_writebyte(uart_id, ((const uint8_t *)buf)[i]);
    }
    fflush(stdout);
    return MSG_OK;
}

/** @brief Write len bytes to UART in hex (2 hex chars per byte).
 *
 *  @param uart_id The id of the uart to write to.
 *  @param type    Message type.
 *  @param buf     Pointer to the bytes to print.
 *  @param len     Number of bytes to print.
 *  @return MSG_OK on success, else other msg_status_t.
 */
int write_hex(int uart_id, msg_type_t type, const void *buf, size_t len) {
    msg_header_t hdr;
    char         hexbuf[128];
    size_t       i;

    hdr.magic = MSG_MAGIC;
    hdr.cmd   = type;
    hdr.len   = (uint16_t)(len * 2);

    write_bytes(uart_id, &hdr, MSG_HEADER_SIZE, false);
    if (type != DEBUG_MSG && read_ack(uart_id) != MSG_OK) {
        return MSG_NO_ACK;
    }

    for (i = 0; i < len; i++) {
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

/** @brief Send a message to the host, expecting an ACK after every 256 bytes.
 *
 *  @param uart_id The id of the uart to write to.
 *  @param type    The type of message to send.
 *  @param buf     Pointer to a buffer containing the outgoing packet.
 *  @param len     The size of the outgoing packet in bytes.
 *  @return MSG_OK on success, else other msg_status_t.
 */
int write_packet(int uart_id, msg_type_t type, const void *buf, uint16_t len) {
    msg_header_t hdr;
    int          result;

    hdr.magic = MSG_MAGIC;
    hdr.cmd   = type;
    hdr.len   = len;

    result = write_bytes(uart_id, &hdr, MSG_HEADER_SIZE, false);

    /* ACKs do not need a response. */
    if (type == ACK_MSG) {
        return result;
    }

    /* Wait for the header ACK before sending the body. */
    if (type != DEBUG_MSG && read_ack(uart_id) != MSG_OK) {
        return MSG_NO_ACK;
    }

    if (len > 0) {
        result = write_bytes(uart_id, buf, len, type != DEBUG_MSG);
        /* ACK the final block (write_bytes does not handle the trailing ACK). */
        if (type != DEBUG_MSG && read_ack(uart_id) != MSG_OK) {
            return MSG_NO_ACK;
        }
    }
    return MSG_OK;
}

/**********************************************************
 ****************** READ PACKET ***************************
 **********************************************************/

/** @brief Reads a packet from UART.
 *
 *  On TRANSFER_INTERFACE, returns MSG_TIMEOUT if the peer stalls.
 *  On CONTROL_INTERFACE, blocks indefinitely waiting for the host.
 *
 *  @param uart_id The id of the uart to read from.
 *  @param cmd     Written with the opcode of the received packet. Must not be null.
 *  @param buf     Buffer to store the packet body. May be null.
 *  @param len     In: max body size; out: actual body length. May be null.
 *  @return MSG_OK on success, MSG_TIMEOUT on peer timeout, negative on error.
 */
int read_packet(int uart_id, msg_type_t *cmd, void *buf, uint16_t *len) {
    msg_header_t header = {0};
    int          result;

    if (cmd == NULL) {
        return MSG_BAD_PTR;
    }

    result = read_header(uart_id, &header);
    if (result != MSG_OK) {
        return result; /* propagates MSG_TIMEOUT */
    }

    *cmd = header.cmd;

    if (len != NULL) {
        if (*len != 0 && header.len > *len) {
            *len = 0;
            return MSG_BAD_LEN;
        }
        *len = header.len;
    }

    if (header.cmd != ACK_MSG) {
        write_ack(uart_id); /* ACK the header */
        if (header.len > 0 && buf != NULL) {
            result = read_bytes(uart_id, buf, header.len);
            if (result != MSG_OK) {
                return result; /* propagates MSG_TIMEOUT */
            }
        }
        if (header.len > 0) {
            result = write_ack(uart_id); /* ACK the final block */
            if (result != MSG_OK) {
                return MSG_NO_ACK;
            }
        }
    }
    return MSG_OK;
}
