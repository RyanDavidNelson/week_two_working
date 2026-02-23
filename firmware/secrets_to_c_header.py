"""
secrets_to_c_header.py — Convert deployment secrets to C header + source.

Generates two files:
  secrets.h  — extern const declarations only (no definitions).
  secrets.c  — full const definitions (compiled once, linked once).

Changes from previous version:

  FIX B (P3/P6): HSM_PIN string literal is no longer emitted.
    PIN_HMAC = HMAC(AUTH_KEY, pin_bytes || "pin") is stored instead.
    check_pin_cmp() (security.c) computes the same HMAC at runtime and
    compares against PIN_HMAC with secure_compare().  An attacker who
    reads flash obtains only the HMAC output.  Recovery requires inverting
    HMAC-SHA256 given AUTH_KEY — infeasible.  More importantly, the power
    trace of wc_HmacUpdate() operating on the input PIN is dominated by
    SHA-256 nonlinear operations, breaking CPA on the comparison.

  FIX D (P4): Previously secrets_to_c_header.py emitted `static const`
    arrays inside secrets.h, causing one copy per translation unit.
    Now it emits `extern const` in secrets.h and full definitions in
    secrets.c.  The caller must add secrets.c to SRCS in the Makefile.

Usage:
    python3 secrets_to_c_header.py <secrets_json> <hsm_pin> <permissions> [--out-dir DIR]

    secrets_json  Path to JSON file from gen_secrets.py
                  (keys: "gcm_key", "auth_key" as hex strings).
    hsm_pin       6 lowercase hex characters (e.g., 1a2b3c).
    permissions   Colon-separated list, e.g. "1234=RWC:aabb=R--".
    --out-dir     Output directory for secrets.h and secrets.c (default: ./inc/).
                  secrets.c is written to <out-dir>/../src/secrets.c.

Author: UTD eCTF Team
Date: 2026
Copyright: Copyright (c) 2026 The MITRE Corporation
"""

import os
import json
import hmac as hmac_mod
import hashlib
import struct
import argparse
from dataclasses import dataclass


@dataclass
class Permission:
    """Represents a permission for one group."""
    group_id: int = None
    read:     bool = False
    write:    bool = False
    receive:  bool = False

    @classmethod
    def deserialize(cls, perms: str):
        """Create a Permission from '<group_id>=<RWC>' string."""
        group_id_str, perm_string = perms.split('=')
        return cls(
            int(group_id_str, 16),
            read    = (perm_string[0] == 'R'),
            write   = (perm_string[1] == 'W'),
            receive = (perm_string[2] == 'C'),
        )

    def serialize(self) -> str:
        ret = f'{self.group_id:04x}='
        for perm, shorthand in {'read': 'R', 'write': 'W', 'receive': 'C'}.items():
            ret += shorthand if getattr(self, perm) else '-'
        return ret

    def to_bytes(self) -> bytes:
        """Serialize: group_id(2 LE) || read(1) || write(1) || receive(1)."""
        return struct.pack(
            '<HBBB',
            self.group_id,
            1 if self.read    else 0,
            1 if self.write   else 0,
            1 if self.receive else 0,
        )


class PermissionList(list):
    """Set of permissions for an HSM."""

    def __init__(self, *args):
        for item in args:
            if isinstance(item, Permission):
                self.append(item)

    @classmethod
    def deserialize(cls, perms: str):
        """Create from colon-separated string, e.g. '1234=RWC:5678=R--'."""
        ret = cls()
        if not perms:
            return ret
        for entry in perms.split(':'):
            entry = entry.strip()
            if entry:
                ret.append(Permission.deserialize(entry))
        return ret

    def serialize(self) -> str:
        return ':'.join(perm.serialize() for perm in self)

    def to_bytes(self) -> bytes:
        return b''.join(perm.to_bytes() for perm in self)


def compute_hmac(key: bytes, data: bytes, domain: bytes) -> bytes:
    """HMAC(key, data || domain) matching firmware hmac_sha256()."""
    return hmac_mod.new(key, data + domain, hashlib.sha256).digest()


def compute_permission_mac(auth_key: bytes, permissions: PermissionList) -> bytes:
    """HMAC(AUTH_KEY, perm_count || permissions || 'permission')."""
    perm_count = len(permissions)
    data = struct.pack('B', perm_count) + permissions.to_bytes()
    return compute_hmac(auth_key, data, b'permission')


def compute_pin_hmac(auth_key: bytes, hsm_pin: str) -> bytes:
    """
    FIX B: HMAC(AUTH_KEY, pin_bytes || 'pin').

    pin_bytes is the raw ASCII bytes of the 6-character hex PIN string
    (e.g., '1a2b3c' → b'1a2b3c'), matching the PIN_LENGTH=6 byte buffer
    that check_pin_cmp() passes to hmac_sha256() in security.c.
    """
    pin_bytes = hsm_pin.encode('ascii')
    return compute_hmac(auth_key, pin_bytes, b'pin')


def bytes_to_c_array(data: bytes, indent: str = '    ', per_line: int = 8) -> str:
    """Convert bytes to C array initializer lines."""
    lines = []
    for i in range(0, len(data), per_line):
        chunk = data[i:i + per_line]
        hex_values = ', '.join(f'0x{b:02x}' for b in chunk)
        lines.append(f'{indent}{hex_values},')
    return '\n'.join(lines)


def perm_to_c(p: Permission) -> str:
    r = 'true' if p.read    else 'false'
    w = 'true' if p.write   else 'false'
    c = 'true' if p.receive else 'false'
    return f'    {{{hex(p.group_id)}, {r}, {w}, {c}}},'


MAX_PERMS = 8


def secrets_to_c_header(
    permissions: PermissionList,
    inc_dir: str,
    src_dir: str,
    hsm_pin: str,
    secrets: bytes,
):
    """
    Generate secrets.h (extern declarations) and secrets.c (definitions).

    FIX B: emits PIN_HMAC instead of raw HSM_PIN.
    FIX D: extern in .h, definitions in .c — no per-TU duplication.
    """
    secrets_dict = json.loads(secrets.decode())
    gcm_key        = bytes.fromhex(secrets_dict['gcm_key'])
    auth_key       = bytes.fromhex(secrets_dict['auth_key'])
    permission_mac = compute_permission_mac(auth_key, permissions)
    pin_hmac       = compute_pin_hmac(auth_key, hsm_pin)  # FIX B
    perm_count     = len(permissions)

    # ------------------------------------------------------------------ #
    # secrets.h — extern declarations only                                #
    # ------------------------------------------------------------------ #
    header_path = os.path.join(inc_dir, 'secrets.h')
    with open(header_path, 'w') as f:
        f.write('/**\n')
        f.write(' * @file secrets.h\n')
        f.write(' * @brief HSM deployment secrets — extern declarations (auto-generated)\n')
        f.write(' * @warning DO NOT COMMIT TO VERSION CONTROL\n')
        f.write(' *\n')
        f.write(' * FIX B: PIN_HMAC replaces raw HSM_PIN.\n')
        f.write(' * FIX D: extern const declarations only; definitions in secrets.c.\n')
        f.write(' */\n\n')
        f.write('#ifndef __SECRETS_H__\n')
        f.write('#define __SECRETS_H__\n\n')
        f.write('#include "security.h"\n')
        f.write('#include <stdint.h>\n\n')
        f.write(f'#define PERM_COUNT {perm_count}\n\n')
        f.write('/* AES-256-GCM key (4-byte aligned for AESADV register load). */\n')
        f.write('extern const uint8_t GCM_KEY[32];\n\n')
        f.write('/* HMAC-SHA256 authentication key. */\n')
        f.write('extern const uint8_t AUTH_KEY[32];\n\n')
        f.write('/* HMAC(AUTH_KEY, perm_count || permissions || "permission"). */\n')
        f.write('extern const uint8_t PERMISSION_MAC[32];\n\n')
        f.write('/* HMAC(AUTH_KEY, pin_bytes || "pin"). FIX B: replaces raw HSM_PIN. */\n')
        f.write('extern const uint8_t PIN_HMAC[32];\n\n')
        f.write('/* Permission table — PERM_COUNT active entries, remainder zero-padded. */\n')
        f.write('extern const group_permission_t global_permissions[MAX_PERMS];\n\n')
        f.write('#endif  /* __SECRETS_H__ */\n')

    # ------------------------------------------------------------------ #
    # secrets.c — full definitions                                        #
    # ------------------------------------------------------------------ #
    source_path = os.path.join(src_dir, 'secrets.c')
    with open(source_path, 'w') as f:
        f.write('/**\n')
        f.write(' * @file secrets.c\n')
        f.write(' * @brief HSM deployment secrets — definitions (auto-generated)\n')
        f.write(' * @warning DO NOT COMMIT TO VERSION CONTROL\n')
        f.write(' *\n')
        f.write(' * FIX B: PIN_HMAC = HMAC(AUTH_KEY, pin_bytes || "pin").\n')
        f.write(' * FIX D: single definition site; secrets.h has only extern decls.\n')
        f.write(' */\n\n')
        f.write('#include "secrets.h"\n\n')

        f.write('/* AES-256-GCM key (4-byte aligned for AESADV register load). */\n')
        f.write('const uint8_t GCM_KEY[32] __attribute__((aligned(4))) = {\n')
        f.write(bytes_to_c_array(gcm_key))
        f.write('\n};\n\n')

        f.write('/* HMAC-SHA256 authentication key. */\n')
        f.write('const uint8_t AUTH_KEY[32] = {\n')
        f.write(bytes_to_c_array(auth_key))
        f.write('\n};\n\n')

        f.write('/* HMAC(AUTH_KEY, perm_count || permissions || "permission"). */\n')
        f.write('const uint8_t PERMISSION_MAC[32] = {\n')
        f.write(bytes_to_c_array(permission_mac))
        f.write('\n};\n\n')

        f.write('/* HMAC(AUTH_KEY, pin_bytes || "pin"). FIX B: replaces raw HSM_PIN. */\n')
        f.write('const uint8_t PIN_HMAC[32] = {\n')
        f.write(bytes_to_c_array(pin_hmac))
        f.write('\n};\n\n')

        f.write(f'/* Permission table — {perm_count} active entries, remainder zero-padded. */\n')
        f.write('const group_permission_t global_permissions[MAX_PERMS] = {\n')
        for p in permissions:
            f.write(perm_to_c(p) + '\n')
        zero_perm = '    {0x0000, false, false, false},'
        for _ in range(MAX_PERMS - len(permissions)):
            f.write(zero_perm + '\n')
        f.write('};\n')

    print(f'Generated: {header_path}')
    print(f'Generated: {source_path}')
    print(f'  PERM_COUNT = {perm_count}')
    print(f'  PIN_HMAC   = {pin_hmac.hex()}  (FIX B: raw PIN not stored)')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Generate secrets.h and secrets.c from deployment secrets.'
    )
    parser.add_argument('secrets',
                        type=argparse.FileType('rb'),
                        help='Path to JSON secrets file from gen_secrets.py')
    parser.add_argument('hsm_pin',
                        type=str,
                        help='6 lowercase hex chars, e.g. 1a2b3c')
    parser.add_argument('permissions',
                        type=str,
                        help='Colon-separated permissions, e.g. "1234=RWC:aabb=R--"')
    parser.add_argument('--out-dir',
                        default='./inc',
                        help='Directory for secrets.h (default: ./inc)')
    args = parser.parse_args()

    # Validate PIN format: exactly 6 lowercase hex chars.
    pin = args.hsm_pin.strip()
    if len(pin) != 6 or not all(c in '0123456789abcdef' for c in pin):
        parser.error('hsm_pin must be exactly 6 lowercase hex characters (0-9, a-f)')

    perms    = PermissionList.deserialize(args.permissions)
    inc_dir  = args.out_dir
    src_dir  = os.path.join(inc_dir, '..', 'src')

    os.makedirs(inc_dir, exist_ok=True)
    os.makedirs(src_dir, exist_ok=True)

    secrets_to_c_header(perms, inc_dir, src_dir, pin, args.secrets.read())
