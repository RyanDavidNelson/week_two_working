/**
 * @file commands.h
 * @brief eCTF command handlers and protocol message structures
 * @date 2026
 *
 * Wire formats use #pragma pack(1); no compiler-inserted padding.
 * Permission bytes on the wire: group_id(2 LE) || read(1) || write(1) || receive(1).
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

/*
 * Serialized size of one group_permission_t on the wire.
 * group_id(2 LE) || read(1) || write(1) || receive(1) = 5 bytes.
 * Must match secrets_to_c_header.py serialization.
 */
#define PERM_SERIAL_SIZE 5

/* Byte length of a list packet body for n files. */
#define LIST_PKT_LEN(num_files) \
    (sizeof(uint32_t) + ((MAX_NAME_SIZE + sizeof(group_id_t) + sizeof(slot_t)) * (uint32_t)(num_files)))

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
 * Round 1  Initiator → Responder  (RECEIVE_MSG)       13 bytes
 * Round 2  Responder → Initiator  (RECEIVE_MSG)       44 bytes
 * Round 3  Initiator → Responder  (RECEIVE_MSG)      105 bytes
 * Round 4  Responder → Initiator  (RECEIVE_MSG)       81 + contents_len bytes
 *
 * R4 layout: nonce(12) || tag(16) || contents_len(2) || uuid(16) ||
 *            slot(1) || group_id(2) || name(32) || ciphertext(contents_len)
 * FILE_DATA_HEADER_SIZE = 81
 * Only FILE_DATA_HEADER_SIZE + contents_len bytes are transmitted in R4.
 *
 * The slot field in receive_r4_t binds the source slot into the wire
 * packet so both sides use the same value when reconstructing the transfer
 * AAD (build_transfer_aad takes slot as a parameter).
 **********************************************************/

/* R1 — Initiator → Responder */
typedef struct {
    uint8_t slot;
    uint8_t recv_chal[NONCE_SIZE];
} receive_r1_t;                             /* 13 bytes */

/* R2 — Responder → Initiator */
typedef struct {
    uint8_t send_chal[NONCE_SIZE];
    uint8_t sender_auth[HMAC_SIZE];         /* HMAC(TAK, recv_chal || "sender") */
} receive_r2_t;                             /* 44 bytes */

/* R3 — Initiator → Responder */
typedef struct {
    uint8_t recv_auth[HMAC_SIZE];           /* HMAC(TAK, send_chal || "receiver") */
    uint8_t perm_count;
    uint8_t perms[MAX_PERMS * PERM_SERIAL_SIZE];
    uint8_t perm_mac[HMAC_SIZE];            /* PERMISSION_MAC */
} receive_r3_t;                             /* 105 bytes */

/*
 * R4 — Responder → Initiator.
 * FILE_DATA_HEADER_SIZE bytes precede the ciphertext.
 * Only FILE_DATA_HEADER_SIZE + contents_len bytes are transmitted.
 */
#define FILE_DATA_HEADER_SIZE \
    (NONCE_SIZE + TAG_SIZE + sizeof(uint16_t) + UUID_SIZE + \
     1U + sizeof(uint16_t) + MAX_NAME_SIZE)
/* = 12 + 16 + 2 + 16 + 1 + 2 + 32 = 81 bytes */

typedef struct {
    uint8_t  nonce[NONCE_SIZE];             /* GCM nonce (TRNG) */
    uint8_t  tag[TAG_SIZE];                 /* GCM authentication tag */
    uint16_t contents_len;                  /* plaintext length */
    uint8_t  uuid[UUID_SIZE];               /* file UUID */
    uint8_t  slot;                          /* source slot (binds AAD) */
    uint16_t group_id;                      /* permission group ID */
    char     name[MAX_NAME_SIZE];           /* null-terminated filename */
    uint8_t  ciphertext[MAX_CONTENTS_SIZE]; /* TRANSFER_KEY encrypted */
} receive_r4_t;                             /* 81-byte header + ciphertext */

/**********************************************************
 ***** INTERROGATE PROTOCOL STRUCTS (TRANSFER INTERFACE) **
 *
 * Round 1  Initiator → Responder  (INTERROGATE_MSG)  117 bytes
 * Round 2  Responder → Initiator  (INTERROGATE_MSG)   32 + list_len bytes
 *
 * R2 layout: resp_auth(32) || list_response body (variable).
 *   Send length = HMAC_SIZE + LIST_PKT_LEN(n_files).
 *   interrogate_r2_t holds the maximum; only the relevant bytes are sent.
 **********************************************************/

/* R1 — Initiator → Responder */
typedef struct {
    uint8_t challenge[NONCE_SIZE];
    uint8_t auth[HMAC_SIZE];                /* HMAC(TAK, challenge || "interrogate_req") */
    uint8_t perm_count;
    uint8_t perms[MAX_PERMS * PERM_SERIAL_SIZE];
    uint8_t perm_mac[HMAC_SIZE];            /* PERMISSION_MAC */
} interrogate_r1_t;                         /* 117 bytes */

/* R2 — Responder → Initiator */
typedef struct {
    uint8_t         resp_auth[HMAC_SIZE];   /* HMAC(TAK, challenge || list || "interrogate_resp") */
    list_response_t list;
} interrogate_r2_t;                         /* 32 + up to 284 bytes */

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
