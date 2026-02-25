
/**
 * @file filesystem.h
 * @brief eCTF flash-based filesystem management
 * @date 2026
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#ifndef __FILESYSTEM__
#define __FILESYSTEM__

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include "simple_flash.h"

typedef unsigned char slot_t;
typedef uint16_t      group_id_t;


/**********************************************************
 ********** BEGIN FUNCTIONALLY DEFINED ELEMENTS ***********
 **********************************************************/

/*
 * FAT scheme, address, and size are defined by the functional requirements.
 * The pointers to files and UUIDs MUST be at this location in flash.
 * Do NOT change MAX_FILE_COUNT, MAX_NAME_SIZE, MAX_CONTENTS_SIZE,
 * _FLASH_FAT_START, or filesystem_entry_t.
 */

#define MAX_FILE_COUNT   8
#define MAX_NAME_SIZE    32
#define MAX_CONTENTS_SIZE 8192

/* FAT resides in the last flash page — mandated by functional spec */
#define _FLASH_FAT_START 0x0003a000

#define UUID_SIZE 16

/* FAT entry — functionally defined layout */
typedef struct {
    char         uuid[UUID_SIZE];
    uint16_t     length;
    uint16_t     padding;
    unsigned int flash_addr;
} filesystem_entry_t;

static filesystem_entry_t FILE_ALLOCATION_TABLE[MAX_FILE_COUNT];

/**********************************************************
 *********** END FUNCTIONALLY DEFINED ELEMENTS ************
 **********************************************************/


/**********************************************************
 ********** FILE STORAGE LAYOUT ***************************
 **********************************************************/

/*
 * Slot flash layout (9 pages = 9216 bytes per slot):
 *   slot 0: 0x10000   slot 1: 0x12400   slot 2: 0x14800   slot 3: 0x16c00
 *   slot 4: 0x19000   slot 5: 0x1b400   slot 6: 0x1d800   slot 7: 0x1fc00
 *
 * FLASH_PAGE_SIZE is provided by simple_flash.h (1024 bytes).
 */
#define FILES_START_ADDR 0x10000
#define FILE_PAGE_COUNT  9
#define STORED_FILE_SIZE (FILE_PAGE_COUNT * FLASH_PAGE_SIZE)

#define FILE_START_PAGE_FROM_SLOT(slot) \
    (FILES_START_ADDR + (STORED_FILE_SIZE * (uint32_t)(slot)))

/*
 * FILE_TOTAL_SIZE: bytes to write/read from flash for a file with
 * contents_len bytes of ciphertext. offsetof gives us the fixed header
 * size up to (but not including) the ciphertext array.
 */
#define FILE_TOTAL_SIZE(len) ((uint32_t)(len) + (uint32_t)offsetof(file_t, ciphertext))

/* Sentinel indicating a slot is occupied */
#define FILE_IN_USE 0xDEADBEEF

/*
 * Stored file structure.
 * Metadata fields (slot, uuid, group_id, name) are plaintext but are
 * bound into the GCM AAD so any tampering invalidates the tag.
 *
 * Layout (packed, total 8277 bytes at maximum ciphertext):
 *   in_use       4 B   — FILE_IN_USE sentinel
 *   slot         1 B   — index (for AAD reconstruction)
 *   uuid        16 B   — copy of file UUID
 *   group_id     2 B   — permission group (LE)
 *   name        32 B   — null-terminated filename
 *   contents_len 2 B   — plaintext length
 *   nonce       12 B   — GCM nonce (TRNG-generated per write)
 *   tag         16 B   — GCM authentication tag
 *   ciphertext 8192 B  — encrypted file contents
 */
#pragma pack(push, 1)
typedef struct {
    uint32_t in_use;                        /* FILE_IN_USE sentinel          */
    uint8_t  slot;                          /* Slot index                    */
    uint8_t  uuid[UUID_SIZE];               /* Copy of file UUID             */
    uint16_t group_id;                      /* Permission group ID           */
    char     name[MAX_NAME_SIZE];           /* Null-terminated filename      */
    uint16_t contents_len;                  /* Original plaintext length     */
    uint8_t  nonce[12];                     /* GCM nonce (TRNG)              */
    uint8_t  tag[16];                       /* GCM authentication tag        */
    uint8_t  ciphertext[MAX_CONTENTS_SIZE]; /* Encrypted contents            */
} file_t;
#pragma pack(pop)


/**********************************************************
 *************** FAT MANAGEMENT ***************************
 **********************************************************/

/** @brief Load FAT from flash into the in-RAM shadow. */
int load_fat(void);

/** @brief Persist the in-RAM FAT shadow to flash. */
int store_fat(void);

/** @brief Initialize filesystem (loads FAT from flash). */
int init_fs(void);

/** @brief Return a read-only pointer to the FAT entry for a slot.
 *  @return Pointer on success, NULL if slot is out of range. */
const filesystem_entry_t *get_file_metadata(slot_t slot);


/**********************************************************
 *************** LOW-LEVEL FILE I/O ***********************
 **********************************************************/

/** @brief Return true if slot holds a live file (FILE_IN_USE sentinel). */
bool is_slot_in_use(slot_t slot);

/** @brief Read the full raw file_t from flash into dest.
 *  @return 0 on success, -1 on invalid slot or NULL dest. */
int read_file(slot_t slot, file_t *dest);

/**
 * @brief Read only the 23-byte header to recover group_id.
 *
 * Avoids placing a full 8KB file_t on the stack. Layout read:
 *   in_use(4) + slot(1) + uuid(16) + group_id(2) = 23 bytes.
 *
 * @param slot         Source slot.
 * @param out_group_id Output: group_id from stored header.
 * @return 0 if slot is in use, -1 if not in use or invalid slot.
 */
int read_file_group_id(slot_t slot, uint16_t *out_group_id);

/** @brief Write raw file_t to flash and update the FAT entry.
 *  @return 0 on success, -1 on invalid inputs. */
int write_file(slot_t slot, file_t *src, const uint8_t *uuid);


/**********************************************************
 *************** SECURE FILE OPERATIONS *******************
 **********************************************************/

/**
 * @brief Encrypt and store a file to flash.
 *
 * Validates inputs, generates a TRNG nonce, builds storage AAD
 * (slot || uuid || group_id || name), GCM-encrypts contents with
 * STORAGE_KEY, and writes the encrypted file_t + FAT entry to flash.
 * The file_t is zeroed before stack unwind regardless of outcome.
 * Permission enforcement is the caller's responsibility.
 *
 * @param slot     Destination slot (0..MAX_FILE_COUNT-1).
 * @param group_id Permission group for this file.
 * @param name     Null-terminated filename (printable ASCII).
 * @param contents Plaintext file contents.
 * @param len      Length of plaintext (must be <= MAX_CONTENTS_SIZE).
 * @param uuid     16-byte file UUID.
 * @return 0 on success, -1 on any failure.
 */
int secure_write_file(slot_t slot, group_id_t group_id, const char *name,
                      const uint8_t *contents, uint16_t len,
                      const uint8_t *uuid);

/**
 * @brief Load, decrypt, and authenticate a file from flash.
 *
 * Reconstructs storage AAD from stored metadata, GCM-decrypts with
 * STORAGE_KEY, and verifies the tag. On any failure the plaintext buffer
 * is zeroed before returning. The local file_t is zeroed in all paths.
 *
 * @param slot          Source slot.
 * @param plaintext     Output buffer (must be >= MAX_CONTENTS_SIZE bytes).
 * @param out_name      Output filename (must be >= MAX_NAME_SIZE bytes).
 * @param out_len       Output: plaintext length in bytes.
 * @param out_group_id  Output: group_id of the decrypted file.
 * @return 0 on success, -1 on any failure (tag mismatch, bad slot, etc.)
 */
int secure_read_file(slot_t slot, uint8_t *plaintext, char *out_name,
                     uint16_t *out_len, uint16_t *out_group_id);

#endif  /* __FILESYSTEM__ */
