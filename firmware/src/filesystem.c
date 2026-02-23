/**
 * @file filesystem.c
 * @brief Filesystem implementation for eCTF HSM
 * @date 2026
 *
 * Key split: secure_write_file() and secure_read_file() pass STORAGE_KEY
 *   explicitly to aes_gcm_encrypt() / aes_gcm_decrypt() so every call site
 *   makes the key choice visible.
 *
 * Fix summary (this revision):
 *   - Removed local #define FILES_START_ADDR and STORED_FILE_SIZE; use the
 *     functionally-required values from filesystem.h.
 *   - write_file / read_file / is_slot_in_use / get_file_metadata / init_fs
 *     signatures now exactly match filesystem.h (slot_t, non-const file_t *).
 *   - flash_simple_read() returns void; removed dead != 0 comparison.
 *   - flash_simple_write() takes void *; removed const qualifier on casts.
 *   - FAT management uses FILE_ALLOCATION_TABLE (in-RAM shadow) consistent
 *     with the reference design.
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#include "filesystem.h"
#include "crypto.h"
#include "security.h"
#include "secrets.h"
#include "simple_flash.h"
#include <string.h>
#include <stddef.h>
#include <stdint.h>


/**********************************************************
 *************** FAT MANAGEMENT ***************************
 **********************************************************/

int load_fat(void)
{
    /* Copy FAT from flash into the in-RAM shadow. */
    flash_simple_read((uint32_t)_FLASH_FAT_START,
                      FILE_ALLOCATION_TABLE,
                      sizeof(FILE_ALLOCATION_TABLE));
    return 0;
}

int store_fat(void)
{
    /* Erase then rewrite the FAT page. */
    flash_simple_erase_page(_FLASH_FAT_START);
    return flash_simple_write((uint32_t)_FLASH_FAT_START,
                              (void *)FILE_ALLOCATION_TABLE,
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
    file_t probe;
    bool   in_use;

    if (!validate_slot(slot)) {
        return false;
    }
    if (read_file(slot, &probe) != 0) {
        return false;
    }

    in_use = (probe.in_use == FILE_IN_USE);
    secure_zero(&probe, sizeof(probe));
    return in_use;
}

int read_file(slot_t slot, file_t *dest)
{
    const uint32_t faddr = FILE_START_PAGE_FROM_SLOT(slot);

    if (!validate_slot(slot) || dest == NULL) {
        return -1;
    }

    /* flash_simple_read() returns void; no return-value check needed. */
    flash_simple_read(faddr, (void *)dest, sizeof(file_t));
    return 0;
}

/* Read only in_use + group_id header (avoids 8 KB stack alloc). */
int read_file_group_id(slot_t slot, uint16_t *out_group_id)
{
    file_t probe;

    if (!validate_slot(slot) || out_group_id == NULL) {
        return -1;
    }
    if (read_file(slot, &probe) != 0) {
        return -1;
    }
    if (probe.in_use != FILE_IN_USE) {
        secure_zero(&probe, sizeof(probe));
        return -1;
    }

    *out_group_id = probe.group_id;
    secure_zero(&probe, sizeof(probe));
    return 0;
}

int write_file(slot_t slot, file_t *src, const uint8_t *uuid)
{
    uint32_t     faddr;
    unsigned int length;
    uint8_t      page_i;

    if (!validate_slot(slot) || src == NULL || uuid == NULL) {
        return -1;
    }
    if (!validate_contents_len(src->contents_len)) {
        return -1;
    }

    faddr  = FILE_START_PAGE_FROM_SLOT(slot);
    length = FILE_TOTAL_SIZE(src->contents_len);

    /* Update in-RAM FAT then persist. */
    memcpy(FILE_ALLOCATION_TABLE[slot].uuid, uuid, UUID_SIZE);
    FILE_ALLOCATION_TABLE[slot].flash_addr = faddr;
    FILE_ALLOCATION_TABLE[slot].length     = (uint16_t)length;
    store_fat();

    /* Erase all pages for this slot before writing. */
    for (page_i = 0; page_i < FILE_PAGE_COUNT; page_i++) {
        flash_simple_erase_page(faddr + (FLASH_PAGE_SIZE * (uint32_t)page_i));
    }

    return flash_simple_write(faddr, (void *)src, length);
}


/**********************************************************
 *************** SECURE FILE OPERATIONS *******************
 **********************************************************/

/*
 * Encrypt and store a file.
 *
 * Generates a fresh 12-byte TRNG nonce, builds storage AAD
 * (slot || uuid || group_id || name), GCM-encrypts the plaintext with
 * STORAGE_KEY, and writes the resulting file_t to flash.
 *
 * Permission enforcement is the caller's responsibility.
 */
int secure_write_file(slot_t slot, group_id_t group_id, const char *name,
                      const uint8_t *contents, uint16_t len,
                      const uint8_t *uuid)
{
    file_t  file;
    uint8_t aad[MAX_AAD_SIZE];
    size_t  aad_len;
    int     enc_result;
    int     write_result;

    if (!validate_slot(slot) || name == NULL || uuid == NULL) {
        return -1;
    }
    if (contents == NULL && len > 0) {
        return -1;
    }
    if (!validate_contents_len(len)) {
        return -1;
    }
    if (!validate_name(name, MAX_NAME_SIZE)) {
        return -1;
    }

    memset(&file, 0, sizeof(file_t));
    file.in_use       = FILE_IN_USE;
    file.slot         = (uint8_t)slot;
    file.group_id     = group_id;
    file.contents_len = len;
    memcpy(file.uuid, uuid, UUID_SIZE);

    strncpy(file.name, name, MAX_NAME_SIZE - 1);
    file.name[MAX_NAME_SIZE - 1] = '\0';

    if (generate_nonce(file.nonce) != 0) {
        secure_zero(&file, sizeof(file_t));
        return -1;
    }

    aad_len = build_storage_aad((uint8_t)slot, uuid, group_id, name, aad);

    /* Encrypt with STORAGE_KEY (at-rest key, separate from TRANSFER_KEY). */
    random_delay();
    enc_result = aes_gcm_encrypt(STORAGE_KEY,
                                 file.nonce,
                                 aad, aad_len,
                                 contents, len,
                                 file.ciphertext,
                                 file.tag);

    secure_zero(aad, sizeof(aad));

    if (enc_result != 0) {
        secure_zero(&file, sizeof(file_t));
        return -1;
    }

    write_result = write_file(slot, &file, uuid);
    secure_zero(&file, sizeof(file_t));

    return (write_result < 0) ? -1 : 0;
}

/*
 * Load, decrypt, and return a file's contents.
 *
 * Reconstructs storage AAD and verifies the GCM tag with STORAGE_KEY.
 * Zeros the plaintext buffer on any failure (tag mismatch or I/O error).
 */
int secure_read_file(slot_t slot, uint8_t *plaintext, char *out_name,
                     uint16_t *out_len, uint16_t *out_group_id)
{
    file_t                    file;
    const filesystem_entry_t *fat_entry;
    uint8_t                   aad[MAX_AAD_SIZE];
    size_t                    aad_len;
    int                       dec_result;

    if (!validate_slot(slot) || plaintext == NULL || out_name == NULL ||
        out_len == NULL || out_group_id == NULL) {
        return -1;
    }

    if (read_file(slot, &file) != 0) {
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

    fat_entry = get_file_metadata(slot);
    if (fat_entry == NULL) {
        secure_zero(&file, sizeof(file_t));
        return -1;
    }

    aad_len = build_storage_aad(
        file.slot,
        (const uint8_t *)fat_entry->uuid,
        file.group_id,
        file.name,
        aad
    );

    /* Decrypt with STORAGE_KEY (at-rest key). */
    random_delay();
    dec_result = aes_gcm_decrypt(STORAGE_KEY,
                                 file.nonce,
                                 aad, aad_len,
                                 file.ciphertext, file.contents_len,
                                 file.tag,
                                 plaintext);

    secure_zero(aad, sizeof(aad));

    if (dec_result != 0) {
        /* GCM tag failed — zero caller's output buffer, return error. */
        secure_zero(plaintext, MAX_CONTENTS_SIZE);
        secure_zero(&file, sizeof(file_t));
        return -1;
    }

    strncpy(out_name, file.name, MAX_NAME_SIZE - 1);
    out_name[MAX_NAME_SIZE - 1] = '\0';
    *out_len      = file.contents_len;
    *out_group_id = file.group_id;

    secure_zero(&file, sizeof(file_t));
    return 0;
}
