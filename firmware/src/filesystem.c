/**
 * @file filesystem.c
 * @brief eCTF flash-based filesystem management
 * @date 2026
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#include <stdint.h>
#include <string.h>

#include "filesystem.h"
#include "simple_flash.h"
#include "security.h"

/*
 * FAT Management
 */

int load_fat(void) {
    flash_simple_read((uint32_t)_FLASH_FAT_START, FILE_ALLOCATION_TABLE, sizeof(FILE_ALLOCATION_TABLE));
    return 0;
}

int store_fat(void) {
    flash_simple_erase_page(_FLASH_FAT_START);
    return flash_simple_write((uint32_t)_FLASH_FAT_START, FILE_ALLOCATION_TABLE, sizeof(FILE_ALLOCATION_TABLE));
}

int init_fs(void) {
    return load_fat();
}

/*
 * File Operations
 */

bool is_slot_in_use(slot_t slot) {
    if (!validate_slot(slot)) {
        return false;
    }
    
    file_t temp_file;
    const int result = read_file(slot, &temp_file);
    
    return (result == 0 && temp_file.in_use == FILE_IN_USE);
}

int create_file(file_t *dest, group_id_t group_id, char *name,
                uint16_t contents_len, uint8_t *contents) {
    if (dest == NULL || name == NULL) {
        return -1;
    }

    if (!validate_contents_len(contents_len)) {
        return -1;
    }

    memset(dest, 0, sizeof(file_t));

    dest->in_use = FILE_IN_USE;
    dest->group_id = group_id;
    dest->contents_len = contents_len;

    strncpy(dest->name, name, MAX_NAME_SIZE - 1);
    dest->name[MAX_NAME_SIZE - 1] = '\0';

    if (contents != NULL && contents_len > 0) {
        memcpy(dest->contents, contents, contents_len);
    }

    return 0;
}

int write_file(slot_t slot, file_t *src, uint8_t *uuid) {
    if (!validate_slot(slot)) {
        return -1;
    }

    if (src == NULL || uuid == NULL) {
        return -1;
    }

    if (!validate_contents_len(src->contents_len)) {
        return -1;
    }

    const unsigned int flash_addr = FILE_START_PAGE_FROM_SLOT(slot);
    const unsigned int length = FILE_TOTAL_SIZE(src->contents_len);

    memcpy(FILE_ALLOCATION_TABLE[slot].uuid, uuid, UUID_SIZE);
    FILE_ALLOCATION_TABLE[slot].flash_addr = flash_addr;
    FILE_ALLOCATION_TABLE[slot].length = length;
    store_fat();

    for (int page_idx = 0; page_idx < FILE_PAGE_COUNT; page_idx++) {
        const unsigned int page_addr = flash_addr + (FLASH_PAGE_SIZE * page_idx);
        flash_simple_erase_page(page_addr);
    }

    return flash_simple_write(FILE_ALLOCATION_TABLE[slot].flash_addr, src, length);
}

int read_file(slot_t slot, file_t *dest) {
    if (!validate_slot(slot)) {
        return -1;
    }

    if (dest == NULL) {
        return -1;
    }

    const unsigned int flash_addr = FILE_ALLOCATION_TABLE[slot].flash_addr;
    const uint16_t file_size = FILE_ALLOCATION_TABLE[slot].length;

    if (file_size > sizeof(file_t)) {
        return -1;
    }

    if (flash_addr < FILES_START_ADDR) {
        return -1;
    }

    flash_simple_read(flash_addr, dest, file_size);

    if (!validate_contents_len(dest->contents_len)) {
        memset(dest, 0, sizeof(file_t));
        return -1;
    }

    return 0;
}

const filesystem_entry_t *get_file_metadata(slot_t slot) {
    if (!validate_slot(slot)) {
        return NULL;
    }
    
    return &FILE_ALLOCATION_TABLE[slot];
}
