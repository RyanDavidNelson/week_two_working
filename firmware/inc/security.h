/**
 * @file security.h
 * @author Samuel Meyers
 * @brief Stub file to hold security checks
 * @date 2026
 *
 * This source file is part of an example system for MITRE's 2026 Embedded CTF (eCTF).
 * This code is being provided only for educational purposes for the 2026 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */
#ifndef __SECURITY_H__
#define __SECURITY_H__

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#define MAX_PERMS 8
#define PIN_LENGTH 6
#define CYCLES_PER_MS 32000

typedef enum {
    PERM_READ = 'R',
    PERM_WRITE = 'W',
    PERM_RECEIVE = 'C',
} permission_enum_t;

typedef struct {
    uint16_t group_id;
    bool read;
    bool write;
    bool receive;
} group_permission_t;

/*
 * Timing Functions
 */

void delay_cycles(uint32_t cycles);
void delay_ms(uint32_t ms);
void random_delay(void);

/*
 * Memory Functions
 */

void secure_zero(void *ptr, size_t len);
void security_halt(void) __attribute__((noreturn));

/*
 * Hardware TRNG Functions
 */

int trng_init(void);
uint32_t trng_read_word(void);
uint8_t trng_read_byte(void);

/*
 * Authentication Functions
 */

bool secure_compare(const void *a, const void *b, size_t len);
bool check_pin(unsigned char *pin);
bool validate_permission(uint16_t group_id, permission_enum_t perm);

/*
 * Input Validation Functions
 */

bool validate_slot(uint8_t slot);
bool validate_name(const char *name, size_t max_len);
bool validate_perm_count(uint8_t count);
bool validate_contents_len(uint16_t len);
bool validate_bool(uint8_t value);

#endif  // __SECURITY_H__
