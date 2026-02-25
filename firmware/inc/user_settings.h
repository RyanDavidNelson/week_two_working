/**
 * @file user_settings.h
 * @brief wolfssl compile-time configuration for eCTF HSM bare-metal target.
 *
 * Activated by -DWOLFSSL_USER_SETTINGS on the compiler command line.
 * When that flag is set, wolfssl/wolfcrypt/settings.h includes this file
 * and skips its own platform-detection logic, so every wolfssl setting is
 * under our explicit control.
 *
 * Only SHA-256, HMAC-SHA256, and AES-256-GCM are enabled.
 * All other algorithms are disabled to minimise flash usage.
 *
 * All defines use #ifndef guards so that any matching -D flag on the
 * compiler command line takes precedence without triggering -Wmacro-redefined.
 *
 * Note on NO_AES_CBC:
 *   This flag was intentionally removed.  In wolfssl 5.7.0, CBC mode
 *   compilation is the gate for the AES lookup tables and GetTable().
 *   GCM's internal AES-ECB block encrypt calls into that same table path,
 *   so disabling CBC inadvertently excludes GCM.  CBC is compiled in but
 *   simply never called; the flash cost is acceptable.
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#ifndef WOLFSSL_USER_SETTINGS_H
#define WOLFSSL_USER_SETTINGS_H

/* ── Build target ──────────────────────────────────────────────────────── */
#ifndef WOLFCRYPT_ONLY
#define WOLFCRYPT_ONLY
#endif
#ifndef SINGLE_THREADED
#define SINGLE_THREADED
#endif
#ifndef NO_FILESYSTEM
#define NO_FILESYSTEM
#endif
#ifndef NO_WRITEV
#define NO_WRITEV
#endif
#ifndef TIME_T_NOT_64BIT
#define TIME_T_NOT_64BIT
#endif

/* ── RNG ───────────────────────────────────────────────────────────────── */
/* All randomness comes from trng_read_byte() in security.c.               */
/* Disabling the wolfcrypt RNG subsystem prevents the compile-time          */
/* "#error No RNG source defined!" in random.h.                            */
#ifndef NO_DEV_RANDOM
#define NO_DEV_RANDOM
#endif
#ifndef WC_NO_HASHDRBG
#define WC_NO_HASHDRBG
#endif
#ifndef WC_NO_RNG
#define WC_NO_RNG
#endif

/* ── AES-256-GCM ───────────────────────────────────────────────────────── */
/* WOLFSSL_AES_GCM : top-level enable processed by settings.h              */
/* HAVE_AES_GCM   : public API gate used by aes.h prototypes               */
/* HAVE_AESGCM    : internal compilation gate used by aes.c function bodies */
/* All three must be set; settings.h may map between them but explicit is   */
/* safer for a bare-metal cross-compile where detection logic may mis-fire. */
#ifndef WOLFSSL_AES_GCM
#define WOLFSSL_AES_GCM
#endif
#ifndef HAVE_AES_GCM
#define HAVE_AES_GCM
#endif
#ifndef HAVE_AESGCM
#define HAVE_AESGCM
#endif

/* ── SHA-256 + HMAC-SHA256 ─────────────────────────────────────────────── */
/* Both are enabled by default; listed explicitly for clarity.              */

/* ── Disabled algorithms ───────────────────────────────────────────────── */
#ifndef NO_MD4
#define NO_MD4
#endif
#ifndef NO_MD5
#define NO_MD5
#endif
#ifndef NO_SHA
#define NO_SHA          /* disables SHA-1 only; SHA-256 remains enabled    */
#endif
#ifndef NO_SHA384
#define NO_SHA384
#endif
#ifndef NO_SHA512
#define NO_SHA512
#endif
#ifndef NO_DES3
#define NO_DES3
#endif
#ifndef NO_RSA
#define NO_RSA
#endif
#ifndef NO_DSA
#define NO_DSA
#endif
#ifndef NO_DH
#define NO_DH
#endif
#ifndef NO_RC4
#define NO_RC4
#endif
#ifndef NO_RABBIT
#define NO_RABBIT
#endif
#ifndef NO_HC128
#define NO_HC128
#endif
#ifndef NO_PSK
#define NO_PSK
#endif
#ifndef NO_PWDBASED
#define NO_PWDBASED
#endif
#ifndef NO_CODING
#define NO_CODING
#endif
#ifndef NO_ASN
#define NO_ASN
#endif
#ifndef NO_CERTS
#define NO_CERTS
#endif
#ifndef NO_SIG_WRAPPER
#define NO_SIG_WRAPPER
#endif

/* ── Misc ──────────────────────────────────────────────────────────────── */
#ifndef HAVE_PK_CALLBACKS
#define HAVE_PK_CALLBACKS
#endif
#ifndef WOLFSSL_USER_IO
#define WOLFSSL_USER_IO
#endif
#ifndef WC_NO_DEFAULT_DEVID
#define WC_NO_DEFAULT_DEVID
#endif
#ifndef NO_CRYPTO_CB
#define NO_CRYPTO_CB
#endif
#ifndef NO_WOLFSSL_DIR
#define NO_WOLFSSL_DIR
#endif

#endif /* WOLFSSL_USER_SETTINGS_H */
