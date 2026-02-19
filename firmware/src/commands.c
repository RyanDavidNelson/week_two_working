/**
 * @file commands.c
 * @brief eCTF command handlers
 * @date 2026
 *
 * Week 1: Input validation at command entry (validate_slot, validate_name,
 *         validate_contents_len).  Uniform "Operation failed" error messages.
 * Week 3: read() and write() use secure_read_file / secure_write_file for
 *         AES-256-GCM encryption at rest.  TOCTOU defense on read.
 *         secure_zero() on all plaintext buffers after use.
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

/** @brief Build list of files on the system.
 *  Reads plaintext metadata (name, group_id) from each occupied slot.
 *  No decryption needed — metadata is not encrypted (bound via GCM AAD). */
void generate_list_files(list_response_t *file_list)
{
    file_list->n_files = 0;
    file_t temp_file;

    for (uint8_t slot = 0; slot < MAX_FILE_COUNT; slot++) {
        if (is_slot_in_use(slot)) {
            read_file(slot, &temp_file);

            const uint32_t idx = file_list->n_files;
            file_list->metadata[idx].slot = slot;
            file_list->metadata[idx].group_id = temp_file.group_id;

            strncpy(file_list->metadata[idx].name,
                    (char *)temp_file.name, MAX_NAME_SIZE - 1);
            file_list->metadata[idx].name[MAX_NAME_SIZE - 1] = '\0';

            file_list->n_files = idx + 1;
        }
    }

    secure_zero(&temp_file, sizeof(file_t));
}

/**********************************************************
 ******************** COMMAND HANDLERS ********************
 **********************************************************/

int list(uint16_t pkt_len, uint8_t *buf)
{
    list_command_t *command = (list_command_t *)buf;
    list_response_t file_list;

    memset(&file_list, 0, sizeof(file_list));
    generate_list_files(&file_list);

    if (!check_pin(command->pin)) {
        print_error("Operation failed");
        return -1;
    }

    pkt_len_t length = LIST_PKT_LEN(file_list.n_files);
    write_packet(CONTROL_INTERFACE, LIST_MSG, &file_list, length);
    return 0;
}

int read(uint16_t pkt_len, uint8_t *buf)
{
    read_command_t *command = (read_command_t *)buf;

    /* --- Week 1: validate slot at entry --- */
    if (!validate_slot(command->slot)) {
        print_error("Operation failed");
        return -1;
    }

    if (!check_pin(command->pin)) {
        print_error("Operation failed");
        return -1;
    }

    /* --- Week 3: permission check BEFORE decryption ---
     * Use lightweight metadata read (23 bytes, no 8KB stack alloc) */
    uint16_t pre_group_id;
    if (read_file_group_id(command->slot, &pre_group_id) != 0) {
        print_error("Operation failed");
        return -1;
    }

    if (!validate_permission(pre_group_id, PERM_READ)) {
        print_error("Operation failed");
        return -1;
    }

    /* --- Week 3: decrypt file via secure_read_file --- */
    read_response_t response;
    memset(&response, 0, sizeof(response));

    uint16_t contents_len = 0;
    uint16_t post_group_id = 0;
    const int dec_result = secure_read_file(
        command->slot,
        (uint8_t *)response.contents,
        response.name,
        &contents_len,
        &post_group_id
    );

    if (dec_result != 0) {
        secure_zero(&response, sizeof(response));
        print_error("Operation failed");
        return -1;
    }

    /* --- Week 3: TOCTOU defense ---
     * Verify group_id from decrypted file matches the one we checked. */
    if (post_group_id != pre_group_id) {
        secure_zero(&response, sizeof(response));
        print_error("Operation failed");
        return -1;
    }

    /* Send the file name + decrypted contents to host */
    const pkt_len_t length = MAX_NAME_SIZE + contents_len;
    write_packet(CONTROL_INTERFACE, READ_MSG, &response, length);

    /* --- Week 3: zero plaintext after sending --- */
    secure_zero(&response, sizeof(response));
    return 0;
}

int write(uint16_t pkt_len, uint8_t *buf)
{
    write_command_t *command = (write_command_t *)buf;

    /* --- Week 1: validate slot at entry --- */
    if (!validate_slot(command->slot)) {
        print_error("Operation failed");
        return -1;
    }

    /* --- Week 1: validate name --- */
    if (!validate_name(command->name, MAX_NAME_SIZE)) {
        print_error("Operation failed");
        return -1;
    }

    /* --- Week 1: validate contents_len --- */
    if (!validate_contents_len(command->contents_len)) {
        print_error("Operation failed");
        return -1;
    }

    if (!check_pin(command->pin)) {
        print_error("Operation failed");
        return -1;
    }

    if (!validate_permission(command->group_id, PERM_WRITE)) {
        print_error("Operation failed");
        return -1;
    }

    /* --- Week 3: encrypt and store via secure_write_file --- */
    const int result = secure_write_file(
        command->slot,
        command->group_id,
        command->name,
        command->contents,
        command->contents_len,
        command->uuid
    );

    if (result != 0) {
        print_error("Operation failed");
        return -1;
    }

    /* Success message with empty body */
    write_packet(CONTROL_INTERFACE, WRITE_MSG, NULL, 0);
    return 0;
}

int receive(uint16_t pkt_len, uint8_t *buf)
{
    receive_command_t *command = (receive_command_t *)buf;
    receive_request_t request;
    receive_response_t recv_resp;
    msg_type_t cmd;
    uint16_t len_recv_msg;

    /* --- Week 1: validate slots at entry --- */
    if (!validate_slot(command->read_slot)) {
        print_error("Operation failed");
        return -1;
    }
    if (!validate_slot(command->write_slot)) {
        print_error("Operation failed");
        return -1;
    }

    if (!check_pin(command->pin)) {
        print_error("Operation failed");
        return -1;
    }

    memset(&recv_resp, 0, sizeof(recv_resp));
    memset(&request, 0, sizeof(request));

    /* Prep request to neighbor */
    request.slot = command->read_slot;
    memcpy(&request.permissions, &global_permissions,
           sizeof(group_permission_t) * MAX_PERMS);

    /* TODO: Week 4 will replace this with secure mutual-auth protocol */
    write_packet(TRANSFER_INTERFACE, RECEIVE_MSG,
                 (void *)&request, sizeof(receive_request_t));

    len_recv_msg = 0xFFFF;

    read_packet(TRANSFER_INTERFACE, &cmd, &recv_resp, &len_recv_msg);
    if (cmd != RECEIVE_MSG) {
        secure_zero(&recv_resp, sizeof(recv_resp));
        print_error("Operation failed");
        return -1;
    }

    /* Store the received (encrypted) file to local flash */
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
    msg_type_t cmd;
    list_response_t final_list_buf;
    uint16_t len_recv_msg;

    if (!check_pin(command->pin)) {
        print_error("Operation failed");
        return -1;
    }

    /* TODO: Week 4 will replace this with authenticated interrogate protocol */
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
    uint8_t uart_buf[sizeof(receive_request_t)];
    msg_type_t cmd;
    pkt_len_t write_length, read_length;
    list_response_t file_list;
    receive_request_t *command;
    receive_response_t recv_resp;
    const filesystem_entry_t *metadata;

    read_length = sizeof(uart_buf);

    memset(uart_buf, 0, sizeof(uart_buf));
    read_packet(TRANSFER_INTERFACE, &cmd, uart_buf, &read_length);

    switch (cmd) {
    case INTERROGATE_MSG:
        /* TODO: Week 4 — add mutual auth, permission filtering */
        memset(&file_list, 0, sizeof(file_list));
        generate_list_files(&file_list);

        write_length = LIST_PKT_LEN(file_list.n_files);
        write_packet(TRANSFER_INTERFACE, INTERROGATE_MSG,
                     &file_list, write_length);
        break;

    case RECEIVE_MSG:
        command = (receive_request_t *)uart_buf;

        if (!validate_slot(command->slot)) {
            print_error("Operation failed");
            return -1;
        }

        /* Send the raw encrypted file_t — no decryption needed.
         * Receiver stores it as-is; AAD is reconstructed on read. */
        memset(&recv_resp, 0, sizeof(recv_resp));

        if (read_file(command->slot, &recv_resp.file) < 0) {
            print_error("Operation failed");
            return -1;
        }

        metadata = get_file_metadata(command->slot);
        if (metadata == NULL) {
            secure_zero(&recv_resp, sizeof(recv_resp));
            print_error("Operation failed");
            return -1;
        }

        memcpy(&recv_resp.uuid, &metadata->uuid, UUID_SIZE);

        /* TODO: Week 4 — mutual auth, re-encrypt for transfer */
        write_length = sizeof(receive_response_t);
        write_packet(TRANSFER_INTERFACE, RECEIVE_MSG,
                     &recv_resp, write_length);

        secure_zero(&recv_resp, sizeof(recv_resp));
        break;

    default:
        print_error("Operation failed");
        return -1;
    }

    write_packet(CONTROL_INTERFACE, LISTEN_MSG, NULL, 0);
    return 0;
}
