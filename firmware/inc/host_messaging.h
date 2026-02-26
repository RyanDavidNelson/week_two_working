/**
 * @file host_messaging.h
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

#ifndef __HOST_MESSAGING__
#define __HOST_MESSAGING__

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "simple_uart.h"

#define CMD_TYPE_LEN sizeof(char)
#define CMD_LEN_LEN  sizeof(uint16_t)
#define MSG_MAGIC    '%'   /* 0x25 */

typedef enum {
    LIST_MSG        = 'L', /* 0x4c */
    READ_MSG        = 'R', /* 0x52 */
    WRITE_MSG       = 'W', /* 0x57 */
    RECEIVE_MSG     = 'C', /* 0x43 */
    INTERROGATE_MSG = 'I', /* 0x49 */
    LISTEN_MSG      = 'N', /* 0x4e */
    ACK_MSG         = 'A', /* 0x41 */
    DEBUG_MSG       = 'D', /* 0x44 */
    ERROR_MSG       = 'E', /* 0x45 */
} msg_type_t;

#pragma pack(push, 1)
typedef struct {
    char     magic; /* Should be MSG_MAGIC */
    char     cmd;   /* msg_type_t */
    uint16_t len;
} msg_header_t;
#pragma pack(pop)

typedef enum {
    MSG_OK      = 0,
    MSG_BAD_PTR,
    MSG_NO_ACK,
    MSG_BAD_LEN,
    MSG_TIMEOUT,   /* TRANSFER_INTERFACE peer did not respond in time */
    /* <0 is UART error */
} msg_status_t;

#define MSG_HEADER_SIZE sizeof(msg_header_t)

/*
 * Maximum number of framing bytes to discard while searching for MSG_MAGIC
 * during header sync on TRANSFER_INTERFACE.  Prevents the sync loop from
 * consuming the entire timeout budget on a corrupted stream.
 */
#define MAX_SYNC_DISCARD 64

int write_bytes(int uart_id, const void *buf, uint16_t len, bool should_ack);

/** @brief Write len bytes to UART in hex (2 hex chars per byte).
 *
 *  @param uart_id The id of the uart where the message is to be sent.
 *  @param type    Message type.
 *  @param buf     Pointer to the bytes that will be printed.
 *  @param len     The number of bytes to print.
 *  @return MSG_OK on success, else other msg_status_t.
 */
int write_hex(int uart_id, msg_type_t type, const void *buf, size_t len);

/** @brief Send a message to the host, ACKing after every 256 bytes.
 *
 *  @param uart_id The id of the uart where the message is to be sent.
 *  @param type    The type of message to send.
 *  @param buf     Pointer to a buffer containing the outgoing packet.
 *  @param len     The size of the outgoing packet in bytes.
 *  @return MSG_OK on success, else other msg_status_t.
 */
int write_packet(int uart_id, msg_type_t type, const void *buf, uint16_t len);

/** @brief Reads a packet from UART.
 *
 *  @param uart_id The id of the uart where the message is to be received.
 *  @param cmd     A pointer to the resulting opcode of the packet. Must not be null.
 *  @param buf     A pointer to a buffer to store the incoming packet. Can be null.
 *  @param len     A pointer to the resulting length of the packet. Can be null.
 *  @return MSG_OK on success, a negative number on failure, MSG_TIMEOUT if
 *          TRANSFER_INTERFACE peer did not send data within the timeout window.
 */
int read_packet(int uart_id, msg_type_t *cmd, void *buf, uint16_t *len);

/* Macro definitions to print the specified format for error messages. */
#define print_error(msg)          write_packet(CONTROL_INTERFACE, ERROR_MSG, msg, strlen(msg))

/* Macro definitions to print the specified format for debug messages. */
#define print_debug(msg)          write_packet(CONTROL_INTERFACE, DEBUG_MSG, msg, strlen(msg))
#define print_hex_debug(msg, len) write_hex(CONTROL_INTERFACE, DEBUG_MSG, msg, len)

/* Macro definition to write ack message. */
#define write_ack(uart_id)        write_packet(uart_id, ACK_MSG, NULL, 0)

#endif /* __HOST_MESSAGING__ */
