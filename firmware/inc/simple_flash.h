
/**
 * @file "simple_flash.h"
 * @author Samuel Meyers
 * @brief Simple Flash Interface Header
 * @date 2026
 *
 * This source file is part of an example system for MITRE's 2026 Embedded CTF (eCTF).
 * This code is being provided only for educational purposes for the 2026 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#ifndef __SIMPLE_FLASH__
#define __SIMPLE_FLASH__

#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <ti/devices/msp/msp.h>
#include <ti/driverlib/driverlib.h>
#include <ti/driverlib/m0p/dl_core.h>

#define FLASH_PAGE_SIZE DL_FLASHCTL_SECTOR_SIZE /* 1024 */

/**
 * @brief Flash Simple Erase Page
 *
 * @param address: uint32_t, address of flash page to erase
 *
 * @return int: return negative if failure, zero if success
 *
 * This function erases a page of flash such that it can be updated.
 * Flash memory can only be erased in a large block size called a page.
 * Once erased, memory can only be written one way e.g. 1->0.
 * In order to be re-written the entire page must be erased.
*/
int flash_simple_erase_page(uint32_t address);

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
int flash_simple_erase_pages(uint32_t address, uint8_t num_pages);

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
void flash_simple_read(uint32_t address, void* buffer, uint32_t size);

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
*/
int flash_simple_write(uint32_t address, void* buffer, uint32_t size);

#endif
