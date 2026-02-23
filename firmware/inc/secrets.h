/**
 * @file secrets.h
 * @brief HSM deployment secrets — extern declarations (auto-generated)
 * @warning DO NOT COMMIT TO VERSION CONTROL
 *
 * FIX B: PIN_HMAC replaces raw HSM_PIN.
 * FIX D: extern const declarations only; definitions in secrets.c.
 */

#ifndef __SECRETS_H__
#define __SECRETS_H__

#include "security.h"
#include <stdint.h>

#define PERM_COUNT 1

/* AES-256-GCM key (4-byte aligned for AESADV register load). */
extern const uint8_t GCM_KEY[32];

/* HMAC-SHA256 authentication key. */
extern const uint8_t AUTH_KEY[32];

/* HMAC(AUTH_KEY, perm_count || permissions || "permission"). */
extern const uint8_t PERMISSION_MAC[32];

/* HMAC(AUTH_KEY, pin_bytes || "pin"). FIX B: replaces raw HSM_PIN. */
extern const uint8_t PIN_HMAC[32];

/* Permission table — PERM_COUNT active entries, remainder zero-padded. */
extern const group_permission_t global_permissions[MAX_PERMS];

#endif  /* __SECRETS_H__ */
