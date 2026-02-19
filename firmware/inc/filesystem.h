/**
 * @file filesystem.h
 * @brief eCTF flash-based filesystem management
 * @date 2026
 *
 * Updated for Week 3: Secure Storage Module.
 * file_t now stores encrypted ciphertext + GCM nonce/tag.
 * secure_write_file() and secure_read_file() provide authenticated
 * encryption at rest via AES-256-GCM with metadata-binding AAD.
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
typedef uint16_t group_id_t;


/**********************************************************
 ********** BEGIN FUNCTIONALLY DEFINED ELEMENTS ***********
 **********************************************************/

/* FAT scheme, address, and size are defined by the functional requirements.
 * The pointers to files and UUIDs MUST be at this location in flash. */

#define MAX_FILE_COUNT 8
#define MAX_NAME_SIZE 32
#define MAX_CONTENTS_SIZE 8192

/* FAT starts at the last flash page — mandated by functional spec */
#define _FLASH_FAT_START 0x0003a000

#define UUID_SIZE 16

/* FAT entry — functionally defined layout */
typedef struct {
    char uuid[UUID_SIZE];
    uint16_t length;
    uint16_t padding;
    unsigned int flash_addr;
} filesystem_entry_t;

static filesystem_entry_t FILE_ALLOCATION_TABLE[MAX_FILE_COUNT];

/**********************************************************
 *********** END FUNCTIONALLY DEFINED ELEMENTS ************
 **********************************************************/


/**********************************************************
 ********** FILE STORAGE LAYOUT (WEEK 3) ******************
 **********************************************************/

/* Sentinel for occupied slot */
#define FILE_IN_USE 0xDEADBEEF

/* Stored file structure — contains encrypted contents + GCM artifacts.
 * Metadata fields (slot, uuid, group_id, name) are plaintext but bound
 * into the GCM AAD, so any tampering breaks the tag. */
#pragma pack(push, 1)
typedef struct {
    uint32_t in_use;                        /* FILE_IN_USE sentinel */
    uint8_t  slot;                          /* Slot index (for AAD reconstruction) */
    uint8_t  uuid[UUID_SIZE];               /* Copy of file UUID */
    uint16_t group_id;                      /* Permission group */
    char     name[MAX_NAME_SIZE];           /* Null-terminated filename */
    uint16_t contents_len;                  /* Original plaintext length */
    uint8_t  nonce[12];                     /* GCM nonce (TRNG-generated) */
    uint8_t  tag[16];                       /* GCM authentication tag */
    uint8_t  ciphertext[MAX_CONTENTS_SIZE]; /* Encrypted file contents */
} file_t;
#pragma pack(pop)

/*
 * Flash layout per slot.  9 pages allocated (9 * 1024 = 9216 bytes).
 * file_t is ~8323 bytes at maximum, fits within 9 pages.
 *
 * Slot addresses:
 *   0: 0x10000  1: 0x12400  2: 0x14800  3: 0x16c00
 *   4: 0x19000  5: 0x1b400  6: 0x1d800  7: 0x1fc00
 */
#define FILES_START_ADDR 0x10000
/* FLASH_PAGE_SIZE provided by simple_flash.h (DL_FLASHCTL_SECTOR_SIZE = 1024) */
#define FILE_PAGE_COUNT 9
#define STORED_FILE_SIZE (FILE_PAGE_COUNT * FLASH_PAGE_SIZE)

#define FILE_START_PAGE_FROM_SLOT(slot) (FILES_START_ADDR + (STORED_FILE_SIZE * (slot)))
#define FILE_TOTAL_SIZE(len) ((len) + offsetof(file_t, ciphertext))


/**********************************************************
 *************** FAT MANAGEMENT ***************************
 **********************************************************/

/** @brief Load FAT from flash into RAM. */
int load_fat(void);

/** @brief Write FAT from RAM to flash. */
int store_fat(void);

/** @brief Initialize filesystem (loads FAT). */
int init_fs(void);

/** @brief Get FAT entry for a slot (NULL on invalid slot). */
const filesystem_entry_t *get_file_metadata(slot_t slot);


/**********************************************************
 *************** LOW-LEVEL FILE I/O ***********************
 **********************************************************/

/** @brief Check whether a slot holds a file.
 *  Validates slot bounds, reads flash, checks FILE_IN_USE sentinel. */
bool is_slot_in_use(slot_t slot);

/** @brief Read raw file_t from flash into dest. */
int read_file(slot_t slot, file_t *dest);

/** @brief Read only in_use + group_id from flash (23 bytes, avoids 8KB stack).
 *  @return 0 if slot is in use, -1 otherwise. */
int read_file_group_id(slot_t slot, uint16_t *out_group_id);

/** @brief Write raw file_t to flash, update FAT with uuid. */
int write_file(slot_t slot, file_t *src, const uint8_t *uuid);


/**********************************************************
 *************** SECURE FILE OPERATIONS (WEEK 3) **********
 **********************************************************/

/** @brief Encrypt and store a file to flash.
 *
 *  Validates inputs, generates TRNG nonce, builds storage AAD
 *  (slot || uuid || group_id || name), GCM-encrypts contents,
 *  and writes the encrypted file_t + FAT entry to flash.
 *
 *  @param slot       Destination slot (0..MAX_FILE_COUNT-1)
 *  @param group_id   Permission group
 *  @param name       Null-terminated filename (printable ASCII)
 *  @param contents   Plaintext file contents
 *  @param len        Length of plaintext
 *  @param uuid       16-byte file UUID
 *  @return 0 on success, -1 on any failure.
 */
int secure_write_file(slot_t slot, group_id_t group_id, const char *name,
                      const uint8_t *contents, uint16_t len,
                      const uint8_t *uuid);

/** @brief Load, decrypt, and authenticate a file from flash.
 *
 *  Reads the encrypted file_t, reconstructs AAD, GCM-decrypts,
 *  and verifies the tag. On tag failure, plaintext buffer is zeroed.
 *
 *  @param slot           Source slot
 *  @param plaintext      Output buffer (at least MAX_CONTENTS_SIZE bytes)
 *  @param out_name       Output filename buffer (at least MAX_NAME_SIZE bytes)
 *  @param out_len        Output: plaintext length
 *  @param out_group_id   Output: file's group_id (for post-decrypt permission check)
 *  @return 0 on success, -1 on any failure (tag failure, bad slot, etc.)
 */
int secure_read_file(slot_t slot, uint8_t *plaintext, char *out_name,
                     uint16_t *out_len, uint16_t *out_group_id);

#endif  /* __FILESYSTEM__ */
