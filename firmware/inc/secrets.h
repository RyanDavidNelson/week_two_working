/**
 * @file secrets.h
 * @brief HSM deployment secrets — extern declarations (auto-generated)
 * @warning DO NOT COMMIT TO VERSION CONTROL
 *
 * Key split (4 keys):
 *   STORAGE_KEY       — AES-256-GCM for files at rest.
 *   TRANSFER_KEY      — AES-256-GCM for files in transit.
 *   TRANSFER_AUTH_KEY — HMAC for protocol auth and PERMISSION_MAC.
 *   PIN_KEY           — HMAC for PIN verification (runtime).
 *
 * Precomputed values:
 *   PERMISSION_MAC = HMAC(TRANSFER_AUTH_KEY, perm_count || perms || "permission")
 *   PIN_HMAC       = HMAC(PIN_KEY, pin_bytes || "pin")
 *
 * FIX B: PIN_HMAC replaces raw HSM_PIN in flash.
 * FIX D: extern declarations only; definitions in secrets.c.
 * FIX PERM: PERMISSION_MAC now uses TRANSFER_AUTH_KEY so runtime
 *           verify_perm_mac() can successfully verify it.
 */

#ifndef __SECRETS_H__
#define __SECRETS_H__

#include "security.h"
#include <stdint.h>

#define PERM_COUNT 1

/* AES-256-GCM key for files at rest (4-byte aligned for AESADV). */
extern const uint8_t STORAGE_KEY[32];

/* AES-256-GCM key for files in transit. */
extern const uint8_t TRANSFER_KEY[32];

/* HMAC-SHA256 key for protocol challenge-response and PERMISSION_MAC. */
extern const uint8_t TRANSFER_AUTH_KEY[32];

/* HMAC-SHA256 key for PIN verification (separate from TRANSFER_AUTH_KEY). */
extern const uint8_t PIN_KEY[32];

/* HMAC(PIN_KEY, pin_bytes || "pin"). Replaces raw HSM_PIN in flash. */
extern const uint8_t PIN_HMAC[32];

/* HMAC(TRANSFER_AUTH_KEY, perm_count || permissions || "permission"). */
extern const uint8_t PERMISSION_MAC[32];

/* Permission table — PERM_COUNT active entries, remainder zero-padded. */
extern const group_permission_t global_permissions[MAX_PERMS];

#endif  /* __SECRETS_H__ */
