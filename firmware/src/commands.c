/**
 * @file commands.c
 * @brief eCTF command handlers
 * @date 2026
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#include <string.h>
#include <stddef.h>

#include "host_messaging.h"
#include "commands.h"
#include "filesystem.h"
#include "security.h"

/*
 * Helper Functions
 */

void generate_list_files(list_response_t *file_list) {
    file_list->n_files = 0;
    file_t temp_file;

    for (uint8_t slot = 0; slot < MAX_FILE_COUNT; slot++) {
        if (is_slot_in_use(slot)) {
            read_file(slot, &temp_file);

            const uint32_t idx = file_list->n_files;
            file_list->metadata[idx].slot = slot;
            file_list->metadata[idx].group_id = temp_file.group_id;
            
            strncpy(file_list->metadata[idx].name, (char *)temp_file.name, MAX_NAME_SIZE - 1);
            file_list->metadata[idx].name[MAX_NAME_SIZE - 1] = '\0';
            
            file_list->n_files = idx + 1;
        }
    }
}

/* Embedded libc does not provide strnlen */
#ifndef HAVE_STRNLEN
static size_t strnlen(const char *s, size_t maxlen) {
    size_t i = 0;
    if (!s) return 0;
    while (i < maxlen && s[i] != '\0') {
        i++;
    }
    return i;
}
#endif

/*
 * Command Handlers
 */

int list(uint16_t pkt_len, uint8_t *buf) {
    list_command_t *command = (list_command_t*)buf;
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

int read(uint16_t pkt_len, uint8_t *buf) {
    read_command_t *command = (read_command_t*)buf;
    read_response_t file_info;
    file_t curr_file;

    if (!validate_slot(command->slot)) {
        print_error("Operation failed");
        return -1;
    }

    if (!check_pin(command->pin)) {
        print_error("Operation failed");
        return -1;
    }

    memset(&file_info, 0, sizeof(read_response_t));

    if (read_file(command->slot, &curr_file) < 0) {
        print_error("Operation failed");
        return -1;
    }

    if (!validate_contents_len(curr_file.contents_len)) {
        print_error("Operation failed");
        return -1;
    }

    if (!validate_permission(curr_file.group_id, PERM_READ)) {
        print_error("Operation failed");
        return -1;
    }

    size_t name_len = strnlen(curr_file.name, MAX_NAME_SIZE);
    if (name_len < MAX_NAME_SIZE) {
        memcpy(file_info.name, curr_file.name, name_len + 1);
    } else {
        memcpy(file_info.name, curr_file.name, MAX_NAME_SIZE - 1);
        file_info.name[MAX_NAME_SIZE - 1] = '\0';
    }

    memcpy(file_info.contents, curr_file.contents, curr_file.contents_len);

    pkt_len_t length = MAX_NAME_SIZE + curr_file.contents_len;
    write_packet(CONTROL_INTERFACE, READ_MSG, &file_info, length);
    return 0;
}

int write(uint16_t pkt_len, uint8_t *buf) {
    write_command_t *command = (write_command_t*)buf;
    file_t curr_file;

    if (!validate_slot(command->slot)) {
        print_error("Operation failed");
        return -1;
    }

    if (!validate_contents_len(command->contents_len)) {
        print_error("Operation failed");
        return -1;
    }

    if (!validate_name(command->name, MAX_NAME_SIZE)) {
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

    create_file(&curr_file, command->group_id, command->name,
                command->contents_len, command->contents);

    if (write_file(command->slot, &curr_file, command->uuid) < 0) {
        print_error("Operation failed");
        return -1;
    }

    write_packet(CONTROL_INTERFACE, WRITE_MSG, NULL, 0);
    return 0;
}

int receive(uint16_t pkt_len, uint8_t *buf) {
    receive_command_t *command = (receive_command_t *)buf;
    receive_request_t request;
    receive_response_t recv_resp;
    msg_type_t cmd;
    uint16_t len_recv_msg;

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

    request.slot = command->read_slot;
    memcpy(&request.permissions, &global_permissions, sizeof(group_permission_t) * MAX_PERMS);

    write_packet(TRANSFER_INTERFACE, RECEIVE_MSG, (void *)&request, sizeof(receive_request_t));

    len_recv_msg = 0xffff;

    read_packet(TRANSFER_INTERFACE, &cmd, &recv_resp, &len_recv_msg);
    if (cmd != RECEIVE_MSG) {
        print_error("Operation failed");
        return -1;
    }

    if (!validate_contents_len(recv_resp.file.contents_len)) {
        print_error("Operation failed");
        return -1;
    }

    if (write_file(command->write_slot, &recv_resp.file, recv_resp.uuid) < 0) {
        print_error("Operation failed");
        return -1;
    }

    write_packet(CONTROL_INTERFACE, RECEIVE_MSG, NULL, 0);
    return 0;
}

int interrogate(uint16_t pkt_len, uint8_t *buf) {
    interrogate_command_t *command = (interrogate_command_t*)buf;
    msg_type_t cmd;
    list_response_t final_list_buf;
    uint16_t len_recv_msg;

    if (!check_pin(command->pin)) {
        print_error("Operation failed");
        return -1;
    }

    write_packet(TRANSFER_INTERFACE, INTERROGATE_MSG, NULL, 0);

    len_recv_msg = 0xffff;

    read_packet(TRANSFER_INTERFACE, &cmd, &final_list_buf, &len_recv_msg);
    if (cmd != INTERROGATE_MSG) {
        print_error("Operation failed");
        return -1;
    }

    write_packet(CONTROL_INTERFACE, INTERROGATE_MSG, &final_list_buf, len_recv_msg);
    return 0;
}

int listen(uint16_t pkt_len, uint8_t *buf) {
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
            memset(&file_list, 0, sizeof(file_list));
            generate_list_files(&file_list);

            write_length = LIST_PKT_LEN(file_list.n_files);
            write_packet(TRANSFER_INTERFACE, INTERROGATE_MSG, &file_list, write_length);
            break;

        case RECEIVE_MSG:
            command = (receive_request_t *)uart_buf;

            if (!validate_slot(command->slot)) {
                print_error("Operation failed");
                return -1;
            }

            if (read_file(command->slot, &recv_resp.file) < 0) {
                print_error("Operation failed");
                return -1;
            }

            metadata = get_file_metadata(command->slot);
            if (metadata == NULL) {
                print_error("Operation failed");
                return -1;
            }

            memcpy(&recv_resp.uuid, &metadata->uuid, UUID_SIZE);

            write_length = sizeof(receive_response_t);
            write_packet(TRANSFER_INTERFACE, RECEIVE_MSG, &recv_resp, write_length);
            break;

        default:
            print_error("Operation failed");
            return -1;
    }

    write_packet(CONTROL_INTERFACE, LISTEN_MSG, NULL, 0);
    return 0;
}
