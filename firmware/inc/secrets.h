/**
 * @file secrets.h
 * @brief HSM deployment secrets — extern declarations (auto-generated)
 * @warning DO NOT COMMIT TO VERSION CONTROL
 *
 * Key split:
 *   STORAGE_KEY       — AES-256-GCM for files at rest.
 *   TRANSFER_KEY      — AES-256-GCM for files in transit.
 *   TRANSFER_AUTH_KEY — HMAC for protocol auth (challenge-response).
 *   PIN_KEY           — HMAC for PIN verification (runtime key).
 *   PERM_KEY (absent) — Used at build time for PERMISSION_MAC only.
 *
 * FIX B: PIN_HMAC replaces raw HSM_PIN.
 * FIX D: extern const declarations only; definitions in secrets.c.
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

/* HMAC-SHA256 key for protocol challenge-response and permission MAC verify. */
extern const uint8_t TRANSFER_AUTH_KEY[32];

/* HMAC-SHA256 key for PIN verification (separate from TRANSFER_AUTH_KEY). */
extern const uint8_t PIN_KEY[32];

/* HMAC(PIN_KEY, pin_bytes || "pin"). FIX B: replaces raw HSM_PIN. */
extern const uint8_t PIN_HMAC[32];

/* HMAC(PERM_KEY, perm_count || permissions || "permission"). PERM_KEY not in firmware. */
extern const uint8_t PERMISSION_MAC[32];

/* Permission table — PERM_COUNT active entries, remainder zero-padded. */
extern const group_permission_t global_permissions[MAX_PERMS];

#endif  /* __SECRETS_H__ */
