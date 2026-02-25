/**
 * @file commands.c
 * @brief eCTF command handlers
 * @date 2026
 *
 * Module 4 changes from week-2 baseline:
 *   - read():  removed direct file_t.contents access; uses secure_read_file()
 *              with read_file_group_id() pre-check and TOCTOU post-check.
 *   - write(): removed create_file() + write_file() pair; uses secure_write_file().
 *   - list():  PIN checked BEFORE generate_list_files() to prevent file-name
 *              leakage on wrong PIN; strncpy with forced null.
 *   - receive() / interrogate() / listen(): week-2 stubs retained unchanged;
 *              these will be replaced in Module 5.
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#include <string.h>
#include <stddef.h>

#include "host_messaging.h"
#include "commands.h"
#include "filesystem.h"
#include "security.h"
#include "crypto.h"
#include "secrets.h"

/**********************************************************
 ******************** HELPER FUNCTIONS ********************
 **********************************************************/

/* Embedded libc may not provide strnlen */
#ifndef HAVE_STRNLEN
static size_t strnlen(const char *s, size_t maxlen)
{
    size_t i = 0;
    if (s == NULL) { return 0; }
    while (i < maxlen && s[i] != '\0') {
        i++;
    }
    return i;
}
#endif

/*
 * Build list of files on the system.
 * Reads plaintext metadata (name, group_id) from each occupied slot.
 * No decryption needed — metadata is not encrypted (bound via GCM AAD).
 * Loop counter slot in [0, MAX_FILE_COUNT).
 */
static void generate_list_files(list_response_t *file_list)
{
    file_t  temp_file;
    uint8_t slot;  /* loop counter */

    file_list->n_files = 0;

    for (slot = 0; slot < MAX_FILE_COUNT; slot++) {
        if (!is_slot_in_use(slot)) {
            continue;
        }

        if (read_file(slot, &temp_file) != 0) {
            continue;
        }

        uint32_t idx = file_list->n_files;
        file_list->metadata[idx].slot     = slot;
        file_list->metadata[idx].group_id = temp_file.group_id;

        /* Bounded copy — no strlen on flash data */
        strncpy(file_list->metadata[idx].name, temp_file.name, MAX_NAME_SIZE - 1);
        file_list->metadata[idx].name[MAX_NAME_SIZE - 1] = '\0';

        file_list->n_files = idx + 1;

        secure_zero(&temp_file, sizeof(temp_file));
    }
}


/**********************************************************
 ******************** COMMAND HANDLERS ********************
 **********************************************************/

/*
 * LIST — return metadata of all files on this HSM.
 * PIN is checked BEFORE generating the list so file names are not
 * leaked to an unauthenticated caller.
 */
int list(uint16_t pkt_len, uint8_t *buf)
{
    list_command_t  *command = (list_command_t *)buf;
    list_response_t  file_list;
    volatile bool    ok1, ok2;

    if (pkt_len < sizeof(list_command_t)) {
        print_error("Operation failed");
        return -1;
    }

    SECURE_PIN_CHECK(ok1, ok2, command->pin);
    secure_zero(command->pin, PIN_LENGTH);
    if (!ok1) {
        delay_ms(5000);
        print_error("Operation failed");
        return -1;
    }

    memset(&file_list, 0, sizeof(file_list));
    generate_list_files(&file_list);

    pkt_len_t length = LIST_PKT_LEN(file_list.n_files);
    write_packet(CONTROL_INTERFACE, LIST_MSG, &file_list, length);
    return 0;
}

/*
 * READ — decrypt and return file contents.
 *
 * Order of operations:
 *   1. Validate slot and packet length.
 *   2. SECURE_PIN_CHECK (halt on glitch, 5 s on wrong PIN).
 *   3. read_file_group_id() — lightweight 23-byte header read, no 8 KB stack alloc.
 *   4. SECURE_BOOL_CHECK(validate_permission(pre_gid, PERM_READ)) — before decrypt.
 *   5. secure_read_file() — decrypt + GCM tag verify.
 *   6. TOCTOU: post_gid must match pre_gid.
 *   7. Send response; zero plaintext.
 */
int read(uint16_t pkt_len, uint8_t *buf)
{
    read_command_t  *command = (read_command_t *)buf;
    volatile bool    ok1, ok2;
    uint16_t         pre_gid  = 0;
    uint16_t         post_gid = 0;
    uint16_t         contents_len = 0;
    read_response_t  response;

    if (pkt_len < sizeof(read_command_t)) {
        print_error("Operation failed");
        return -1;
    }

    if (!validate_slot(command->slot)) {
        print_error("Operation failed");
        return -1;
    }

    SECURE_PIN_CHECK(ok1, ok2, command->pin);
    secure_zero(command->pin, PIN_LENGTH);
    if (!ok1) {
        delay_ms(5000);
        print_error("Operation failed");
        return -1;
    }

    /* Permission check BEFORE decrypt — read group_id from flash header only */
    if (read_file_group_id(command->slot, &pre_gid) != 0) {
        print_error("Operation failed");
        return -1;
    }

    SECURE_BOOL_CHECK(ok1, ok2, validate_permission(pre_gid, PERM_READ));
    if (!ok1) {
        print_error("Operation failed");
        return -1;
    }

    /* Decrypt via STORAGE_KEY; GCM tag verified inside secure_read_file() */
    memset(&response, 0, sizeof(response));
    if (secure_read_file(command->slot,
                         (uint8_t *)response.contents,
                         response.name,
                         &contents_len,
                         &post_gid) != 0) {
        secure_zero(&response, sizeof(response));
        print_error("Operation failed");
        return -1;
    }

    if (!validate_contents_len(contents_len)) {
        secure_zero(&response, sizeof(response));
        print_error("Operation failed");
        return -1;
    }

    /* TOCTOU: group_id must not have changed between the header read and decrypt */
    if (post_gid != pre_gid) {
        secure_zero(&response, sizeof(response));
        print_error("Operation failed");
        return -1;
    }

    pkt_len_t length = (pkt_len_t)(MAX_NAME_SIZE + contents_len);
    write_packet(CONTROL_INTERFACE, READ_MSG, &response, length);

    secure_zero(&response, sizeof(response));
    return 0;
}

/*
 * WRITE — encrypt and store a file.
 * Uses secure_write_file() which generates a fresh TRNG nonce and encrypts
 * with STORAGE_KEY. Permission checked before the flash write.
 *
 * write_command_t is variable-length: the struct ends with
 *   uint16_t contents_len; uint8_t contents[MAX_CONTENTS_SIZE];
 * The tool sends only header + actual file bytes, NOT the full 8 KB tail.
 * Minimum valid packet = everything up to (not including) contents[].
 */
#define WRITE_CMD_HEADER_SIZE  ((uint16_t)offsetof(write_command_t, contents))

int write(uint16_t pkt_len, uint8_t *buf)
{
    write_command_t *command = (write_command_t *)buf;
    volatile bool    ok1, ok2;

    /* The host tool sends the full write_command_t struct (fixed 8251 B),
     * not a trimmed packet.  Only check that the fixed header fields arrived.
     * secure_write_file() uses command->contents_len to bound the copy. */
    if (pkt_len < WRITE_CMD_HEADER_SIZE) {
        print_debug("write:W1 short pkt");
        print_error("Operation failed");
        return -1;
    }

    if (!validate_slot(command->slot)) {
        print_debug("write:W2 bad slot");
        print_error("Operation failed");
        return -1;
    }

    if (!validate_contents_len(command->contents_len)) {
        print_debug("write:W3 bad len");
        print_error("Operation failed");
        return -1;
    }

    /* Ensure the packet contains at least as many bytes as declared. */
    if (pkt_len < (uint16_t)(WRITE_CMD_HEADER_SIZE + command->contents_len)) {
        print_debug("write:W4 truncated");
        print_error("Operation failed");
        return -1;
    }

    if (!validate_name(command->name, MAX_NAME_SIZE)) {
        print_debug("write:W5 bad name");
        print_error("Operation failed");
        return -1;
    }

    SECURE_PIN_CHECK(ok1, ok2, command->pin);
    secure_zero(command->pin, PIN_LENGTH);
    if (!ok1) {
        delay_ms(5000);
        print_debug("write:W6 bad pin");
        print_error("Operation failed");
        return -1;
    }

    SECURE_BOOL_CHECK(ok1, ok2, validate_permission(command->group_id, PERM_WRITE));
    if (!ok1) {
        print_debug("write:W7 no perm");
        print_error("Operation failed");
        return -1;
    }

    if (secure_write_file(command->slot,
                          command->group_id,
                          command->name,
                          command->contents,
                          command->contents_len,
                          command->uuid) != 0) {
        print_debug("write:W8 crypto fail");
        print_error("Operation failed");
        return -1;
    }

    write_packet(CONTROL_INTERFACE, WRITE_MSG, NULL, 0);
    return 0;
}


/**********************************************************
 ***** RECEIVE / INTERROGATE / LISTEN — Week-2 stubs ******
 *
 * These will be replaced with the full mutual-auth protocol in Module 5.
 * They compile cleanly against the new file_t layout because they only
 * access fields that are still present (contents_len, group_id, name).
 **********************************************************/

int receive(uint16_t pkt_len, uint8_t *buf)
{
    receive_command_t  *command = (receive_command_t *)buf;
    receive_request_t   request;
    receive_response_t  recv_resp;
    msg_type_t          cmd;
    uint16_t            len_recv_msg;

    if (!validate_slot(command->read_slot) || !validate_slot(command->write_slot)) {
        print_error("Operation failed");
        return -1;
    }

    if (!check_pin(command->pin)) {
        print_error("Operation failed");
        return -1;
    }
    secure_zero(command->pin, PIN_LENGTH);

    memset(&recv_resp, 0, sizeof(recv_resp));
    memset(&request,   0, sizeof(request));

    request.slot = command->read_slot;
    memcpy(&request.permissions, &global_permissions,
           sizeof(group_permission_t) * MAX_PERMS);

    /* TODO: Module 5 — replace with 4-round mutual-auth protocol */
    write_packet(TRANSFER_INTERFACE, RECEIVE_MSG,
                 (void *)&request, sizeof(receive_request_t));

    len_recv_msg = 0xFFFF;
    read_packet(TRANSFER_INTERFACE, &cmd, &recv_resp, &len_recv_msg);
    if (cmd != RECEIVE_MSG) {
        secure_zero(&recv_resp, sizeof(recv_resp));
        print_error("Operation failed");
        return -1;
    }

    if (!validate_contents_len(recv_resp.file.contents_len)) {
        secure_zero(&recv_resp, sizeof(recv_resp));
        print_error("Operation failed");
        return -1;
    }

    if (write_file(command->write_slot, &recv_resp.file, recv_resp.uuid) < 0) {
        secure_zero(&recv_resp, sizeof(recv_resp));
        print_error("Operation failed");
        return -1;
    }

    secure_zero(&recv_resp, sizeof(recv_resp));
    write_packet(CONTROL_INTERFACE, RECEIVE_MSG, NULL, 0);
    return 0;
}

int interrogate(uint16_t pkt_len, uint8_t *buf)
{
    interrogate_command_t *command = (interrogate_command_t *)buf;
    msg_type_t             cmd;
    list_response_t        final_list_buf;
    uint16_t               len_recv_msg;

    if (!check_pin(command->pin)) {
        print_error("Operation failed");
        return -1;
    }
    secure_zero(command->pin, PIN_LENGTH);

    /* TODO: Module 5 — replace with authenticated interrogate protocol */
    write_packet(TRANSFER_INTERFACE, INTERROGATE_MSG, NULL, 0);

    len_recv_msg = 0xFFFF;
    read_packet(TRANSFER_INTERFACE, &cmd, &final_list_buf, &len_recv_msg);
    if (cmd != INTERROGATE_MSG) {
        print_error("Operation failed");
        return -1;
    }

    write_packet(CONTROL_INTERFACE, INTERROGATE_MSG, &final_list_buf, len_recv_msg);
    return 0;
}

int listen(uint16_t pkt_len, uint8_t *buf)
{
    uint8_t                uart_buf[sizeof(receive_request_t)];
    msg_type_t             cmd;
    pkt_len_t              write_length;
    uint16_t               read_length;
    list_response_t        file_list;
    receive_request_t     *request;
    receive_response_t     recv_resp;
    const filesystem_entry_t *metadata;

    read_length = sizeof(uart_buf);
    memset(uart_buf, 0, sizeof(uart_buf));
    read_packet(TRANSFER_INTERFACE, &cmd, uart_buf, &read_length);

    switch (cmd) {
    case INTERROGATE_MSG:
        /* TODO: Module 5 — add mutual auth, permission filtering */
        memset(&file_list, 0, sizeof(file_list));
        generate_list_files(&file_list);
        write_length = LIST_PKT_LEN(file_list.n_files);
        write_packet(TRANSFER_INTERFACE, INTERROGATE_MSG, &file_list, write_length);
        break;

    case RECEIVE_MSG:
        request = (receive_request_t *)uart_buf;

        if (!validate_slot(request->slot)) {
            print_error("Operation failed");
            return -1;
        }

        memset(&recv_resp, 0, sizeof(recv_resp));

        if (read_file(request->slot, &recv_resp.file) < 0) {
            secure_zero(&recv_resp, sizeof(recv_resp));
            print_error("Operation failed");
            return -1;
        }

        metadata = get_file_metadata(request->slot);
        if (metadata == NULL) {
            secure_zero(&recv_resp, sizeof(recv_resp));
            print_error("Operation failed");
            return -1;
        }

        memcpy(recv_resp.uuid, metadata->uuid, UUID_SIZE);

        /* TODO: Module 5 — mutual auth, re-encrypt for transfer */
        write_length = sizeof(receive_response_t);
        write_packet(TRANSFER_INTERFACE, RECEIVE_MSG, &recv_resp, write_length);
        secure_zero(&recv_resp, sizeof(recv_resp));
        break;

    default:
        print_error("Operation failed");
        return -1;
    }

    write_packet(CONTROL_INTERFACE, LISTEN_MSG, NULL, 0);
    return 0;
}
