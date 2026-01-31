/**
 * @file test_security.h
 * @brief Test and calibration routines header for security module
 * @date 2026
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#ifndef __TEST_SECURITY_H__
#define __TEST_SECURITY_H__

/**
 * @brief Run all security module tests
 * 
 * Runs calibration and tests for:
 * - busy_wait timing calibration
 * - TRNG initialization and random number generation
 * - secure_compare function
 * - Input validators
 * - explicit_bzero function
 */
void run_security_tests(void);

/**
 * @brief Calibrate the busy_wait_ms function
 * 
 * Measures actual CPU cycles per millisecond and outputs
 * the recommended CYCLES_PER_MS value.
 */
void calibrate_busy_wait(void);

/**
 * @brief Test TRNG functionality
 * 
 * Initializes TRNG and reads some random values.
 */
void test_trng(void);

/**
 * @brief Test secure_compare function
 */
void test_secure_compare(void);

/**
 * @brief Test input validation functions
 */
void test_validators(void);

/**
 * @brief Test explicit_bzero function
 */
void test_explicit_bzero(void);

/**
 * @brief Test PIN checking with timing measurement
 * 
 * WARNING: This test takes 5+ seconds due to wrong PIN delay
 */
void test_pin_timing(void);

#endif  /* __TEST_SECURITY_H__ */
