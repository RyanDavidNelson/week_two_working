/**
 * @file filesystem.c
 * @brief eCTF flash-based filesystem management
 * @date 2026
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#include <stdint.h>
#include <string.h>
#include <stddef.h>

#include "filesystem.h"
#include "simple_flash.h"
#include "security.h"
#include "crypto.h"


/**********************************************************
 *************** FAT MANAGEMENT ***************************
 **********************************************************/

int load_fat(void)
{
    flash_simple_read((uint32_t)_FLASH_FAT_START,
                      FILE_ALLOCATION_TABLE,
                      sizeof(FILE_ALLOCATION_TABLE));
    return 0;
}

int store_fat(void)
{
    flash_simple_erase_page(_FLASH_FAT_START);
    return flash_simple_write((uint32_t)_FLASH_FAT_START,
                              FILE_ALLOCATION_TABLE,
                              sizeof(FILE_ALLOCATION_TABLE));
}

int init_fs(void)
{
    return load_fat();
}

const filesystem_entry_t *get_file_metadata(slot_t slot)
{
    if (!validate_slot(slot)) {
        return NULL;
    }
    return &FILE_ALLOCATION_TABLE[slot];
}


/**********************************************************
 *************** LOW-LEVEL FILE I/O ***********************
 **********************************************************/

bool is_slot_in_use(slot_t slot)
{
    if (!validate_slot(slot)) {
        return false;
    }

    /* Read only the in_use sentinel (4 bytes) instead of full 8KB file_t */
    uint32_t in_use = 0;
    const unsigned int flash_addr = FILE_START_PAGE_FROM_SLOT(slot);
    flash_simple_read(flash_addr, &in_use, sizeof(in_use));

    return (in_use == FILE_IN_USE);
}

int read_file(slot_t slot, file_t *dest)
{
    if (!validate_slot(slot)) {
        return -1;
    }
    if (dest == NULL) {
        return -1;
    }

    const unsigned int flash_addr = FILE_START_PAGE_FROM_SLOT(slot);
    flash_simple_read(flash_addr, dest, sizeof(file_t));
    return 0;
}

/* Read only the metadata prefix of file_t (23 bytes) to extract group_id.
 * Avoids putting a full 8KB+ file_t on the caller's stack. */
int read_file_group_id(slot_t slot, uint16_t *out_group_id)
{
    if (!validate_slot(slot) || out_group_id == NULL) {
        return -1;
    }

    /* file_t packed layout: in_use(4) + slot(1) + uuid(16) + group_id(2) = 23 */
    uint8_t header[23];
    const unsigned int flash_addr = FILE_START_PAGE_FROM_SLOT(slot);
    flash_simple_read(flash_addr, header, sizeof(header));

    uint32_t in_use;
    memcpy(&in_use, header, sizeof(uint32_t));
    if (in_use != FILE_IN_USE) {
        return -1;
    }

    memcpy(out_group_id, header + 21, sizeof(uint16_t));
    return 0;
}

int write_file(slot_t slot, file_t *src, const uint8_t *uuid)
{
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
    /* Total bytes: metadata + ciphertext (contents_len bytes of ct) */
    const unsigned int length = FILE_TOTAL_SIZE(src->contents_len);

    /* Update FAT */
    memcpy(FILE_ALLOCATION_TABLE[slot].uuid, uuid, UUID_SIZE);
    FILE_ALLOCATION_TABLE[slot].flash_addr = flash_addr;
    FILE_ALLOCATION_TABLE[slot].length = length;
    store_fat();

    /* Erase pages for this slot */
    for (uint8_t page_i = 0; page_i < FILE_PAGE_COUNT; page_i++) {
        flash_simple_erase_page(flash_addr + (FLASH_PAGE_SIZE * page_i));
    }

    /* Write file_t to flash */
    return flash_simple_write(flash_addr, src, length);
}


/**********************************************************
 *************** SECURE FILE OPERATIONS (WEEK 3) **********
 **********************************************************/

int secure_write_file(slot_t slot, group_id_t group_id, const char *name,
                      const uint8_t *contents, uint16_t len,
                      const uint8_t *uuid)
{
    /* --- Input validation --- */
    if (!validate_slot(slot)) {
        return -1;
    }
    if (!validate_contents_len(len)) {
        return -1;
    }
    if (!validate_name(name, MAX_NAME_SIZE)) {
        return -1;
    }
    if (contents == NULL && len > 0) {
        return -1;
    }
    if (uuid == NULL || name == NULL) {
        return -1;
    }

    file_t file;
    memset(&file, 0, sizeof(file_t));

    /* --- Populate metadata (plaintext, bound via AAD) --- */
    file.in_use = FILE_IN_USE;
    file.slot = (uint8_t)slot;
    memcpy(file.uuid, uuid, UUID_SIZE);
    file.group_id = group_id;

    strncpy(file.name, name, MAX_NAME_SIZE - 1);
    file.name[MAX_NAME_SIZE - 1] = '\0';

    file.contents_len = len;

    /* --- Generate 12-byte nonce via TRNG --- */
    if (generate_nonce(file.nonce) != 0) {
        secure_zero(&file, sizeof(file_t));
        return -1;
    }

    /* --- Build storage AAD: slot(1) || uuid(16) || group_id(2) || name(32) --- */
    uint8_t aad[MAX_AAD_SIZE];
    const size_t aad_len = build_storage_aad(slot, uuid, group_id, name, aad);

    /* --- GCM encrypt: plaintext → ciphertext + tag --- */
    random_delay();
    const int enc_result = aes_gcm_encrypt(
        file.nonce,
        aad, aad_len,
        contents, len,
        file.ciphertext,
        file.tag
    );

    if (enc_result != 0) {
        secure_zero(&file, sizeof(file_t));
        secure_zero(aad, sizeof(aad));
        return -1;
    }

    secure_zero(aad, sizeof(aad));

    /* --- Write encrypted file_t + FAT entry to flash --- */
    const int write_result = write_file(slot, &file, uuid);
    secure_zero(&file, sizeof(file_t));

    return (write_result < 0) ? -1 : 0;
}

int secure_read_file(slot_t slot, uint8_t *plaintext, char *out_name,
                     uint16_t *out_len, uint16_t *out_group_id)
{
    /* --- Validate parameters --- */
    if (!validate_slot(slot)) {
        return -1;
    }
    if (plaintext == NULL || out_name == NULL ||
        out_len == NULL || out_group_id == NULL) {
        return -1;
    }

    /* --- Load encrypted file_t from flash --- */
    file_t file;
    if (read_file(slot, &file) < 0) {
        return -1;
    }
    if (file.in_use != FILE_IN_USE) {
        secure_zero(&file, sizeof(file_t));
        return -1;
    }
    if (!validate_contents_len(file.contents_len)) {
        secure_zero(&file, sizeof(file_t));
        return -1;
    }

    /* --- Get UUID from FAT for AAD reconstruction --- */
    const filesystem_entry_t *fat_entry = get_file_metadata(slot);
    if (fat_entry == NULL) {
        secure_zero(&file, sizeof(file_t));
        return -1;
    }

    /* --- Rebuild storage AAD from stored metadata --- */
    uint8_t aad[MAX_AAD_SIZE];
    const size_t aad_len = build_storage_aad(
        file.slot,
        (const uint8_t *)fat_entry->uuid,
        file.group_id,
        file.name,
        aad
    );

    /* --- GCM decrypt + tag verification --- */
    random_delay();
    const int dec_result = aes_gcm_decrypt(
        file.nonce,
        aad, aad_len,
        file.ciphertext, file.contents_len,
        file.tag,
        plaintext
    );

    secure_zero(aad, sizeof(aad));

    if (dec_result != 0) {
        /* Tag verification failed — zero everything */
        secure_zero(plaintext, MAX_CONTENTS_SIZE);
        secure_zero(&file, sizeof(file_t));
        return -1;
    }

    /* --- Copy metadata to caller --- */
    strncpy(out_name, file.name, MAX_NAME_SIZE - 1);
    out_name[MAX_NAME_SIZE - 1] = '\0';
    *out_len = file.contents_len;
    *out_group_id = file.group_id;

    secure_zero(&file, sizeof(file_t));
    return 0;
}
