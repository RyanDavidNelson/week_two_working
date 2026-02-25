/**
 * @file secrets.h
 * @brief HSM deployment secrets — extern declarations (auto-generated)
 * @warning DO NOT COMMIT TO VERSION CONTROL
 *
 * wolfcrypt migration: STORAGE_KEY_H, TRANSFER_KEY_H, DUMMY_GCM_KEY, and
 * DUMMY_GCM_KEY_H have been removed.  wolfcrypt derives the GCM hash
 * subkey internally; no pre-computed H value is required at build time.
 */

#ifndef __SECRETS_H__
#define __SECRETS_H__

#include "security.h"
#include <stdint.h>

/* Number of active entries in global_permissions[]. */
#define PERM_COUNT 1

/* AES-256-GCM key for files at rest. */
extern const uint8_t STORAGE_KEY[32];

/* AES-256-GCM key for files in transit. */
extern const uint8_t TRANSFER_KEY[32];

/* HMAC-SHA256 key for protocol challenge-response and PERMISSION_MAC. */
extern const uint8_t TRANSFER_AUTH_KEY[32];

/* HMAC-SHA256 key for PIN verification (separate from TRANSFER_AUTH_KEY). */
extern const uint8_t PIN_KEY[32];

/* HMAC(PIN_KEY, pin_bytes || "pin") — raw PIN is never stored. */
extern const uint8_t PIN_HMAC[32];

/* HMAC(TRANSFER_AUTH_KEY, perm_count || perms || "permission"). */
extern const uint8_t PERMISSION_MAC[32];

/* Permission table — PERM_COUNT active entries, remainder zero-padded. */
extern const group_permission_t global_permissions[MAX_PERMS];

#endif  /* __SECRETS_H__ */
