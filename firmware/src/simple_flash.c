/**
 * @file "simple_flash.c"
 * @author Samuel Meyers
 * @brief Simple Flash Interface Implementation
 * @date 2026
 *
 * This source file is part of an example system for MITRE's 2026 Embedded CTF (eCTF).
 * This code is being provided only for educational purposes for the 2026 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#include "simple_flash.h"

/**
 * @brief Flash Simple Erase Page
 *
 * @param address: uint32_t, address of flash page to erase
 *
 * @return int: return negative if failure, zero if success
 *
 * This function erases a page of flash such that it can be updated.
 * Flash memory can only be erased in a large block size called a page (or sector).
 * Once erased, memory can only be written one way e.g. 1->0.
 * In order to be re-written the entire page must be erased.
*/
int flash_simple_erase_page(uint32_t address) {
    volatile DL_FLASHCTL_COMMAND_STATUS cmdStatus;
    DL_FlashCTL_executeClearStatus(FLASHCTL);
    DL_FlashCTL_unprotectSector(FLASHCTL, address, DL_FLASHCTL_REGION_SELECT_MAIN);

    cmdStatus = DL_FlashCTL_eraseMemoryFromRAM(
        FLASHCTL, address, DL_FLASHCTL_COMMAND_SIZE_SECTOR);
    if (cmdStatus == DL_FLASHCTL_COMMAND_STATUS_FAILED) {
        return -1;
    }
    /* returns a boolean, so handle that accordingly */
    bool ret = DL_FlashCTL_waitForCmdDone(FLASHCTL);
    if (ret == false) {
        return -1;
    }
    return 0;
}

/**
 * @brief Flash Simple Erase Pages
 *
 * @param address:   uint32_t, address of first flash page to erase
 * @param num_pages: uint8_t,  number of contiguous pages to erase
 *
 * @return int: return negative if any page erase fails, zero if all succeed
 *
 * Erases num_pages contiguous flash pages starting at address.
 * Symmetric counterpart to flash_simple_write() for multi-page operations.
 * Loop counter page_i in [0, num_pages); terminates when page_i == num_pages.
*/
int flash_simple_erase_pages(uint32_t address, uint8_t num_pages) {
    uint8_t page_i; /* loop counter — terminates at num_pages */

    for (page_i = 0; page_i < num_pages; page_i++) {
        if (flash_simple_erase_page(address + (FLASH_PAGE_SIZE * (uint32_t)page_i)) != 0) {
            return -1;
        }
    }
    return 0;
}

/**
 * @brief Flash Simple Read
 *
 * @param address: uint32_t, address of flash page to read
 * @param buffer: void*, pointer to buffer for data to be read into
 * @param size: uint32_t, number of bytes to read from flash
 *
 * This function reads data from the specified flash page into the buffer
 * with the specified amount of bytes
*/
void flash_simple_read(uint32_t address, void* buffer, uint32_t size) {
    /* flash is memory mapped, and the flash controller has no read functionality */
    memcpy(buffer, (void *)address, size);
}

/**
 * @brief Flash Simple Write
 *
 * @param address: uint32_t, address of flash page to write
 * @param buffer: void*, pointer to buffer to write data from
 * @param size: uint32_t, number of bytes to write from flash
 *
 * @return int: return negative if failure, zero if success
 *
 * This function writes data to the specified flash page from the buffer passed
 * with the specified amount of bytes. Flash memory can only be written in one
 * way e.g. 1->0. To rewrite previously written memory see the
 * flash_simple_erase_page documentation.
 *
 * STACK FIX: the original used a VLA sized to the entire write (up to ~8280 B
 * for a max file), which overflowed the stack when secure_write_file() already
 * held a file_t (~8277 B) in the same call chain.  The fix stages one
 * FLASH_PAGE_SIZE chunk at a time into a static buffer (1032 B), keeping peak
 * stack growth for this function near zero.  Callers (write_file, store_fat)
 * already erase all target pages before calling here, so writing page-by-page
 * is safe.  unprotectSector is called per chunk because protection state is
 * per-sector; the original only unprotected the first sector, which was a
 * latent bug for multi-page writes.
*/
int flash_simple_write(uint32_t address, void* buffer, uint32_t size) {
    volatile DL_FLASHCTL_COMMAND_STATUS cmdStatus;
    bool     ret;
    uint32_t offset;       /* byte offset into buffer — loop counter            */
    uint32_t chunk_bytes;  /* bytes in this iteration (≤ FLASH_PAGE_SIZE)       */
    uint32_t chunk_words;  /* 32-bit words to program, rounded up to even count */

    /*
     * Static staging buffer: replaces the former VLA.
     *
     * Worst-case chunk_words derivation (chunk_bytes ≤ FLASH_PAGE_SIZE = 1024):
     *   chunk_bytes = 1024 → chunk_words = 256 (already even, no rounding)
     *   chunk_bytes = 1023 → 1023/4 = 255 (odd)  → round word up → 256
     *   chunk_bytes = 1022 → 1022/4 = 255 (odd)  → round word up → 256
     *   chunk_bytes = 1021 → 1021/4 = 255 (odd)  → round word up → 256
     * Maximum chunk_words is 256 for any chunk.
     * Buffer sized at (FLASH_PAGE_SIZE/4) + 2 = 258 words for safe margin.
     */
    static uint32_t write_page[(FLASH_PAGE_SIZE / 4) + 2]; /* 258 × 4 = 1032 B */

    DL_FlashCTL_executeClearStatus(FLASHCTL);

    /* Write one flash page at a time.
     * Loop counter offset in [0, size); terminates when offset >= size. */
    for (offset = 0; offset < size; offset += FLASH_PAGE_SIZE) {

        /* Bytes remaining vs. one full page. */
        chunk_bytes = (size - offset < (uint32_t)FLASH_PAGE_SIZE)
                      ? (size - offset) : (uint32_t)FLASH_PAGE_SIZE;

        /* Round up to a 32-bit word count, then ensure even (ECC requirement). */
        chunk_words = (chunk_bytes % 4u == 0u)
                      ? (chunk_bytes / 4u) : (chunk_bytes / 4u) + 1u;
        chunk_words = (chunk_words % 2u == 0u) ? chunk_words : chunk_words + 1u;

        /* Stage chunk into the static aligned buffer; pad tail with 0xFF. */
        memset(write_page, 0xFF, chunk_words * 4u);
        memcpy(write_page, (const uint8_t *)buffer + offset, chunk_bytes);

        /* Each sector requires its own unprotect call before programming. */
        DL_FlashCTL_unprotectSector(FLASHCTL, address + offset,
                                    DL_FLASHCTL_REGION_SELECT_MAIN);

        /* Program function expects size in 32-bit words. */
        cmdStatus = DL_FlashCTL_programMemoryBlockingFromRAM64WithECCGenerated(
            FLASHCTL, address + offset, write_page, chunk_words,
            DL_FLASHCTL_REGION_SELECT_MAIN);
        if (cmdStatus == DL_FLASHCTL_COMMAND_STATUS_FAILED) {
            return -1;
        }
        /* Returns a boolean, so handle that accordingly. */
        ret = DL_FlashCTL_waitForCmdDone(FLASHCTL);
        if (ret == false) {
            return -1;
        }
    }
    return 0;
}
