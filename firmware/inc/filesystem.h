/**
 * @file filesystem.h
 * @brief Filesystem interface for eCTF HSM
 * @date 2026
 *
 * Flash layout (MSPM0L2228):
 *   _FLASH_FAT_START     — one FLASH_PAGE_SIZE page holding the FAT
 *   FILES_START_ADDR     — file data begins here; 9 pages per slot
 *
 * FILE_ALLOCATION_TABLE is defined once in filesystem.c and declared
 * extern here.  The old `static` definition in the header caused every
 * translation unit that included filesystem.h to get its own private copy
 * of the FAT — a latent multi-TU divergence bug that could silently produce
 * inconsistent FAT state after a write if any future refactor includes this
 * header from a second .c file.
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#ifndef __FILESYSTEM__
#define __FILESYSTEM__

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "security.h"

/* ------------------------------------------------------------------ */
/* Flash layout constants                                              */
/* ------------------------------------------------------------------ */

/* FLASH_PAGE_SIZE (1024) is defined by simple_flash.h via DL_FLASHCTL_SECTOR_SIZE.
 * Do not redefine it here. */
#define _FLASH_FAT_START    0x00000000U

/* Each file slot occupies 9 flash pages: 1 metadata + 8 content. */
#define FILE_PAGE_COUNT     9U
#define STORED_FILE_SIZE    (FLASH_PAGE_SIZE * FILE_PAGE_COUNT)

/* First flash address for file data (FAT occupies page 0). */
#define FILES_START_ADDR    0x10000U

#define FILE_START_PAGE_FROM_SLOT(slot) \
    (FILES_START_ADDR + (STORED_FILE_SIZE * (uint32_t)(slot)))

/* ------------------------------------------------------------------ */
/* File structure constants                                            */
/* ------------------------------------------------------------------ */

#define UUID_SIZE           16U
#define FILE_IN_USE         0xDEADBEEFU

/* file_t header byte count through the 'name' field (used by
 * read_file_header() to avoid placing an 8277-byte file_t on the stack). */
#define FILE_HEADER_SIZE    55U   /* in_use(4)+slot(1)+uuid(16)+group_id(2)+name(32) */

/* Total on-flash byte count of a file with the given plaintext length. */
#define FILE_TOTAL_SIZE(len) ((uint32_t)(len) + (uint32_t)offsetof(file_t, ciphertext))

/* ------------------------------------------------------------------ */
/* Types                                                               */
/* ------------------------------------------------------------------ */

typedef uint8_t  slot_t;
typedef uint16_t group_id_t;

/*
 * On-flash file structure.  pragma pack(1) ensures no compiler padding so
 * that offsetof() arithmetic in FILE_TOTAL_SIZE() and read_file_header()
 * produces the correct byte offsets.
 *
 * Layout (packed, total 8277 bytes at maximum ciphertext):
 *   in_use        4 B  — FILE_IN_USE sentinel
 *   slot          1 B  — index (for AAD reconstruction)
 *   uuid         16 B  — copy of file UUID
 *   group_id      2 B  — permission group (LE)
 *   name         32 B  — null-terminated filename
 *   contents_len  2 B  — plaintext length
 *   nonce        12 B  — GCM nonce (TRNG-generated per write)
 *   tag          16 B  — GCM authentication tag
 *   ciphertext 8192 B  — AES-GCM encrypted contents
 */
#pragma pack(push, 1)
typedef struct {
    uint32_t   in_use;                        /* FILE_IN_USE sentinel          */
    uint8_t    slot;                          /* slot index                    */
    uint8_t    uuid[UUID_SIZE];               /* 16-byte file UUID             */
    uint16_t   group_id;                      /* permission group (LE)         */
    char       name[MAX_NAME_SIZE];           /* null-terminated filename      */
    uint16_t   contents_len;                 /* plaintext byte count          */
    uint8_t    nonce[12];                     /* GCM nonce (TRNG)              */
    uint8_t    tag[16];                       /* GCM authentication tag        */
    uint8_t    ciphertext[MAX_CONTENTS_SIZE]; /* AES-GCM encrypted contents    */
} file_t;
#pragma pack(pop)

/*
 * Lightweight header struct for the LSN-INT filter loop.
 * Mirrors the first FILE_HEADER_SIZE bytes of file_t without the
 * 8192-byte contents array.
 */
typedef struct {
    uint32_t   in_use;
    uint8_t    slot;
    uint8_t    uuid[UUID_SIZE];
    group_id_t group_id;
    char       name[MAX_NAME_SIZE];
} file_header_t;

/* FAT entry — stores flash address, byte length, and UUID per slot. */
typedef struct {
    uint32_t flash_addr;
    uint16_t length;
    uint8_t  uuid[UUID_SIZE];
} filesystem_entry_t;

/* ------------------------------------------------------------------ */
/* FAT shadow — defined once in filesystem.c                          */
/* ------------------------------------------------------------------ */

/*
 * FILE_ALLOCATION_TABLE is the in-RAM shadow of the on-flash FAT.
 * Defined in filesystem.c; extern here so only one copy exists at link time.
 *
 * The previous `static filesystem_entry_t FILE_ALLOCATION_TABLE[...]`
 * definition in the header gave each TU its own private array.  Any TU
 * that called write_file() or store_fat() would update filesystem.c's copy
 * but leave its own silent stale copy intact — a bug waiting for a future
 * refactor that includes filesystem.h from a second .c file.
 */
extern filesystem_entry_t FILE_ALLOCATION_TABLE[MAX_FILE_COUNT];

/* ------------------------------------------------------------------ */
/* FAT management                                                      */
/* ------------------------------------------------------------------ */

/** @brief Load FAT from flash into the in-RAM shadow. */
int load_fat(void);

/** @brief Persist the in-RAM FAT shadow to flash. */
int store_fat(void);

/** @brief Initialize filesystem (loads FAT from flash). */
int init_fs(void);

/** @brief Return a read-only pointer to the FAT entry for a slot.
 *  @return Pointer on success, NULL if slot is out of range. */
const filesystem_entry_t *get_file_metadata(slot_t slot);

/* ------------------------------------------------------------------ */
/* Low-level file I/O                                                  */
/* ------------------------------------------------------------------ */

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

/**
 * @brief Read the 55-byte packed header (in_use through name) without
 *  allocating a full file_t.
 *
 * Layout read: in_use(4) + slot(1) + uuid(16) + group_id(2) + name(32) = 55 B.
 *
 * @param slot  Source slot.
 * @param out   Output file_header_t; zeroed by caller on error paths.
 * @return 0 if slot is in use, -1 if not in use or invalid slot/dest.
 */
int read_file_header(slot_t slot, file_header_t *out);

/** @brief Write raw file_t to flash and update the FAT entry.
 *  @return 0 on success, -1 on invalid inputs. */
int write_file(slot_t slot, file_t *src, const uint8_t *uuid);

/* ------------------------------------------------------------------ */
/* Secure file operations                                              */
/* ------------------------------------------------------------------ */

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
