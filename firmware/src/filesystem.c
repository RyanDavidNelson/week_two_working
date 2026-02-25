/**
 * @file filesystem.c
 * @brief Filesystem implementation for eCTF HSM
 * @date 2026
 *
 * Key split: secure_write_file() and secure_read_file() pass STORAGE_KEY
 *   explicitly to aes_gcm_encrypt() / aes_gcm_decrypt() so every call
 *   site makes the key choice visible.
 *
 * AAD design: storage AAD = slot(1) || uuid(16) || group_id(2 LE) || name(32).
 *   UUID for AAD reconstruction in secure_read_file() is taken from file.uuid
 *   (written into the file_t at encrypt time) rather than the FAT, keeping
 *   the AAD self-consistent regardless of FAT state.
 *
 * read_file_group_id() reads only 23 header bytes to recover group_id without
 *   placing a full 8 KB file_t on the stack.
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

/*
 * Read the full raw file_t from flash.
 * FILE_START_PAGE_FROM_SLOT() gives the flash address even before the FAT
 * is populated (e.g. first boot).
 */
int read_file(slot_t slot, file_t *dest)
{
    uint32_t faddr;

    if (!validate_slot(slot) || dest == NULL) {
        return -1;
    }

    faddr = FILE_START_PAGE_FROM_SLOT(slot);
    /* flash_simple_read() returns void; no return-value check needed. */
    flash_simple_read(faddr, (void *)dest, sizeof(file_t));
    return 0;
}

/*
 * Read only the 23-byte header to recover group_id.
 *
 * Packed offsets inside file_t (verified against #pragma pack(1)):
 *   [0..3]   in_use      (4 B, uint32_t)
 *   [4]      slot        (1 B, uint8_t)
 *   [5..20]  uuid        (16 B, uint8_t[16])
 *   [21..22] group_id    (2 B, uint16_t, LE)  ← target
 *
 * Avoids placing a full 8 KB file_t on the stack for a single field read.
 */
int read_file_group_id(slot_t slot, uint16_t *out_group_id)
{
    uint8_t  header[23];   /* in_use(4) + slot(1) + uuid(16) + group_id(2) */
    uint32_t faddr;
    uint32_t in_use_val;

    if (!validate_slot(slot) || out_group_id == NULL) {
        return -1;
    }

    faddr = FILE_START_PAGE_FROM_SLOT(slot);
    flash_simple_read(faddr, header, sizeof(header));

    /* Check sentinel before trusting any other header field. */
    memcpy(&in_use_val, header, sizeof(uint32_t));
    if (in_use_val != FILE_IN_USE) {
        return -1;
    }

    /* group_id lives at byte offset 21 (4 + 1 + 16) in the packed struct. */
    memcpy(out_group_id, header + 21, sizeof(uint16_t));
    return 0;
}

/*
 * Write a file_t to flash and update the FAT.
 * Erases all FILE_PAGE_COUNT pages for the slot before writing.
 */
int write_file(slot_t slot, file_t *src, const uint8_t *uuid)
{
    uint32_t     faddr;
    unsigned int length;
    uint8_t      page_i;   /* loop counter — terminates at FILE_PAGE_COUNT */

    if (!validate_slot(slot) || src == NULL || uuid == NULL) {
        return -1;
    }
    if (!validate_contents_len(src->contents_len)) {
        return -1;
    }

    faddr  = FILE_START_PAGE_FROM_SLOT(slot);
    length = FILE_TOTAL_SIZE(src->contents_len);

    /* Persist UUID and address in in-RAM FAT, then write FAT to flash. */
    memcpy(FILE_ALLOCATION_TABLE[slot].uuid, uuid, UUID_SIZE);
    FILE_ALLOCATION_TABLE[slot].flash_addr = faddr;
    FILE_ALLOCATION_TABLE[slot].length     = (uint16_t)length;
    store_fat();

    /* Erase all pages for this slot before writing.
     * page_i < FILE_PAGE_COUNT ensures we never exceed the allocation. */
    for (page_i = 0; page_i < FILE_PAGE_COUNT; page_i++) {
        flash_simple_erase_page(faddr + (FLASH_PAGE_SIZE * (uint32_t)page_i));
    }

    return flash_simple_write(faddr, (void *)src, length);
}


/**********************************************************
 *************** SECURE FILE OPERATIONS *******************
 **********************************************************/

/*
 * Encrypt and store a file with STORAGE_KEY.
 *
 * Generates a fresh 12-byte TRNG nonce per write (nonce reuse is impossible).
 * Storage AAD = slot(1) || uuid(16) || group_id(2 LE) || name(32 zero-padded).
 * The local file_t is zeroed before return in all paths.
 * Permission enforcement is the caller's responsibility.
 */
int secure_write_file(slot_t slot, group_id_t group_id, const char *name,
                      const uint8_t *contents, uint16_t len,
                      const uint8_t *uuid)
{
    file_t  file;
    uint8_t aad[STORAGE_AAD_SIZE];
    size_t  aad_len;
    int     enc_result;
    int     write_result;

    /* --- Input validation --- */
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

    /* --- Populate file metadata (plaintext, integrity-protected via AAD) --- */
    memset(&file, 0, sizeof(file_t));
    file.in_use       = FILE_IN_USE;
    file.slot         = (uint8_t)slot;
    file.group_id     = group_id;
    file.contents_len = len;
    memcpy(file.uuid, uuid, UUID_SIZE);
    strncpy(file.name, name, MAX_NAME_SIZE - 1);
    file.name[MAX_NAME_SIZE - 1] = '\0';

    /* --- Generate fresh 12-byte TRNG nonce --- */
    if (generate_nonce(file.nonce) != 0) {
        secure_zero(&file, sizeof(file_t));
        return -1;
    }

    /* --- Build storage AAD: slot || uuid || group_id || name (51 bytes) --- */
    aad_len = build_storage_aad((uint8_t)slot, uuid, group_id, name, aad);

    /* --- AES-256-GCM encrypt with STORAGE_KEY (at-rest key) --- */
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

    /* --- Write encrypted file_t and update FAT --- */
    write_result = write_file(slot, &file, uuid);
    secure_zero(&file, sizeof(file_t));

    return (write_result < 0) ? -1 : 0;
}

/*
 * Load, decrypt, and authenticate a file from flash.
 *
 * Reconstructs storage AAD from the stored metadata fields (slot, uuid,
 * group_id, name) then decrypts with STORAGE_KEY.  UUID is taken from
 * file.uuid (written at encrypt time) so the AAD is self-consistent even
 * if the FAT is re-loaded from flash between the write and the read.
 *
 * The GCM tag is verified inside aes_gcm_decrypt(); on failure the
 * plaintext buffer is zeroed before returning -1.
 * The local file_t is zeroed before return in all paths.
 */
int secure_read_file(slot_t slot, uint8_t *plaintext, char *out_name,
                     uint16_t *out_len, uint16_t *out_group_id)
{
    file_t  file;
    uint8_t aad[STORAGE_AAD_SIZE];
    size_t  aad_len;
    int     dec_result;

    if (!validate_slot(slot) || plaintext == NULL ||
        out_name == NULL || out_len == NULL || out_group_id == NULL) {
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

    /* Reconstruct AAD using embedded UUID — must match what was built at write time. */
    aad_len = build_storage_aad(
        file.slot,
        file.uuid,       /* embedded UUID, not FAT copy */
        file.group_id,
        file.name,
        aad
    );

    /* --- AES-256-GCM decrypt with STORAGE_KEY (at-rest key) --- */
    random_delay();
    dec_result = aes_gcm_decrypt(STORAGE_KEY,
                                 file.nonce,
                                 aad, aad_len,
                                 file.ciphertext, file.contents_len,
                                 file.tag,
                                 plaintext);

    secure_zero(aad, sizeof(aad));

    if (dec_result != 0) {
        /* Tag failure — zero caller's buffer, do not leak partial plaintext. */
        secure_zero(plaintext, MAX_CONTENTS_SIZE);
        secure_zero(&file, sizeof(file_t));
        return -1;
    }

    /* Copy output fields only after successful authentication. */
    strncpy(out_name, file.name, MAX_NAME_SIZE - 1);
    out_name[MAX_NAME_SIZE - 1] = '\0';
    *out_len      = file.contents_len;
    *out_group_id = file.group_id;

    secure_zero(&file, sizeof(file_t));
    return 0;
}
