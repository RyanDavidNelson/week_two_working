/**
 * @file commands.h
 * @brief eCTF command handlers and protocol message structures
 * @date 2026
 *
 * Week 4: Full authenticated transfer protocol structures.
 *   RECEIVE:     3-round mutual-auth handshake + GCM-encrypted file transfer.
 *   INTERROGATE: Challenge-response + permission-filtered file list.
 *
 * Wire formats use explicit byte layouts (no struct padding ambiguity).
 * Permission fields serialized as group_id(2 LE) || read(1) || write(1) || receive(1).
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#ifndef __COMMANDS_H__
#define __COMMANDS_H__

#include "security.h"
#include "crypto.h"
#include "stdint.h"
#include "simple_flash.h"
#include "filesystem.h"
#include "secrets.h"

#define pkt_len_t uint16_t

/* 6 hex characters 0-9, a-f */
typedef unsigned char pin_t[6];

#define MAX_MSG_SIZE sizeof(write_command_t)

/* Serialized size of one group_permission_t on the wire:
 * group_id(2 LE) || read(1) || write(1) || receive(1) = 5 bytes.
 * Must match the Python serialization in secrets_to_c_header.py. */
#define PERM_SERIAL_SIZE 5

/* Byte length of a list packet body */
#define LIST_PKT_LEN(num_files) \
    (sizeof(uint32_t) + ((MAX_NAME_SIZE + sizeof(group_id_t) + sizeof(slot_t)) * (num_files)))

#pragma pack(push, 1)

/**********************************************************
 ******************** FILE METADATA ***********************
 **********************************************************/

typedef struct {
    slot_t     slot;
    group_id_t group_id;
    char       name[MAX_NAME_SIZE];
} file_metadata_t;

/**********************************************************
 ********* HOST → HSM COMMAND STRUCTS (CONTROL) ***********
 **********************************************************/

typedef struct {
    pin_t pin;
} list_command_t;

typedef struct {
    pin_t  pin;
    slot_t slot;
} read_command_t;

typedef struct {
    pin_t      pin;
    slot_t     slot;
    group_id_t group_id;
    char       name[MAX_NAME_SIZE];
    uint8_t    uuid[UUID_SIZE];
    uint16_t   contents_len;
    uint8_t    contents[MAX_CONTENTS_SIZE];
} write_command_t;

typedef struct {
    pin_t  pin;
    slot_t read_slot;
    slot_t write_slot;
} receive_command_t;

typedef struct {
    pin_t pin;
} interrogate_command_t;

/**********************************************************
 ********* HSM → HOST RESPONSE STRUCTS (CONTROL) **********
 **********************************************************/

typedef struct {
    uint32_t        n_files;
    file_metadata_t metadata[MAX_FILE_COUNT];
} list_response_t;

typedef struct {
    char    name[MAX_NAME_SIZE];
    uint8_t contents[MAX_CONTENTS_SIZE];
} read_response_t;

/**********************************************************
 ******* RECEIVE PROTOCOL STRUCTS (TRANSFER INTERFACE) ****
 *
 * Round 1 — Requester → Responder  (RECEIVE_MSG):
 *   receive_request_t { slot(1), receiver_challenge(12) }   = 13 bytes
 *
 * Round 2 — Responder → Requester  (RECEIVE_MSG):
 *   challenge_response_t { sender_challenge(12), sender_auth(32) }  = 44 bytes
 *
 * Round 3 — Requester → Responder  (RECEIVE_MSG):
 *   permission_proof_t { receiver_auth(32), perm_count(1),
 *                        perms(MAX_PERMS*5=40), mac(32) }  = 105 bytes
 *
 * Round 4 — Responder → Requester  (RECEIVE_MSG):
 *   Packed wire layout:
 *     uuid(16) || group_id(2) || contents_len(2) || name(32)
 *     || transfer_nonce(12) || tag(16) || ciphertext(contents_len)
 *
 *   send_len = FILE_DATA_HEADER_SIZE + contents_len  (= 80 + contents_len)
 *
 * CRITICAL STRUCT LAYOUT NOTE:
 *   tag[] MUST remain immediately before ciphertext[] so that
 *   write_packet() serializes the tag in the correct position for the
 *   receiver.  Moving tag to after ciphertext[MAX_CONTENTS_SIZE] would
 *   cause the tag to be serialized at the wrong offset for files shorter
 *   than MAX_CONTENTS_SIZE, breaking GCM authentication on every transfer.
 **********************************************************/

typedef struct {
    slot_t  slot;
    uint8_t receiver_challenge[NONCE_SIZE];
} receive_request_t;                        /* 13 bytes */

typedef struct {
    uint8_t sender_challenge[NONCE_SIZE];
    uint8_t sender_auth[HMAC_SIZE];
} challenge_response_t;                     /* 44 bytes */

typedef struct {
    uint8_t receiver_auth[HMAC_SIZE];
    uint8_t perm_count;
    uint8_t permissions_bytes[MAX_PERMS * PERM_SERIAL_SIZE]; /* zero-padded */
    uint8_t permission_mac[HMAC_SIZE];
} permission_proof_t;                       /* 105 bytes */

/*
 * FILE_DATA_HEADER_SIZE: fixed fields before ciphertext.
 * uuid(16) + group_id(2) + contents_len(2) + name(32) + nonce(12) + tag(16) = 80 bytes.
 * Wire packet length = FILE_DATA_HEADER_SIZE + contents_len.
 */
#define FILE_DATA_HEADER_SIZE \
    (UUID_SIZE + sizeof(uint16_t) + sizeof(uint16_t) \
     + MAX_NAME_SIZE + NONCE_SIZE + TAG_SIZE)
/* = 80 bytes */

typedef struct {
    uint8_t  uuid[UUID_SIZE];               /* 16 */
    uint16_t group_id;                      /*  2 */
    uint16_t contents_len;                  /*  2 */
    char     name[MAX_NAME_SIZE];           /* 32 */
    uint8_t  transfer_nonce[NONCE_SIZE];    /* 12 */
    uint8_t  tag[TAG_SIZE];                 /* 16 — before ciphertext so it serializes correctly */
    uint8_t  ciphertext[MAX_CONTENTS_SIZE]; /* 8192 — only contents_len bytes transmitted */
} file_data_t;

/**********************************************************
 ***** INTERROGATE PROTOCOL STRUCTS (TRANSFER INTERFACE) **
 *
 * Round 1 — Requester → Responder  (INTERROGATE_MSG):
 *   interrogate_request_t { challenge(12), auth(32), perm_count(1),
 *                           perms(MAX_PERMS*5=40), mac(32) }  = 117 bytes
 *
 * Round 2 — Responder → Requester  (INTERROGATE_MSG):
 *   response_auth(32) || list_response body (variable, max 284 bytes)
 *   Received into interrogate_response_t (max 316 bytes).
 **********************************************************/

typedef struct {
    uint8_t challenge[NONCE_SIZE];
    uint8_t auth[HMAC_SIZE];
    uint8_t perm_count;
    uint8_t permissions_bytes[MAX_PERMS * PERM_SERIAL_SIZE];
    uint8_t permission_mac[HMAC_SIZE];
} interrogate_request_t;                    /* 117 bytes */

typedef struct {
    uint8_t         response_auth[HMAC_SIZE];
    list_response_t file_list;
} interrogate_response_t;                   /* 32 + max 284 = 316 bytes */

#pragma pack(pop)

/**********************************************************
 ******************** COMMAND HANDLERS ********************
 **********************************************************/

int list(uint16_t pkt_len, uint8_t *buf);
int read(uint16_t pkt_len, uint8_t *buf);
int write(uint16_t pkt_len, uint8_t *buf);
int receive(uint16_t pkt_len, uint8_t *buf);
int interrogate(uint16_t pkt_len, uint8_t *buf);
int listen(uint16_t pkt_len, uint8_t *buf);

#endif /* __COMMANDS_H__ */
