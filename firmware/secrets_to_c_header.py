"""
secrets_to_c_header.py — Convert deployment secrets to C header + source.

Generates two files:
  secrets.h  — extern const declarations only (no definitions).
  secrets.c  — full const definitions (compiled once, linked once).

Key split (from gen_secrets.py):

  STORAGE_KEY (32 B)       — Runtime.  AES-256-GCM for files at rest.
  TRANSFER_KEY (32 B)      — Runtime.  AES-256-GCM for files in transit.
  TRANSFER_AUTH_KEY (32 B) — Runtime.  HMAC for protocol auth (sender/
                             receiver/interrogate/permission MAC verify).
  PIN_KEY (32 B)           — Runtime.  HMAC for PIN verification.
                             Separate from TRANSFER_AUTH_KEY so CPA on
                             PIN check does not expose the protocol key.
  PERM_KEY (32 B)          — Build-time only.  Used here to compute
                             PERMISSION_MAC; NOT emitted to secrets.h/c.

Precomputed values written to firmware:
  PERMISSION_MAC = HMAC(PERM_KEY,  perm_count || permissions || "permission")
  PIN_HMAC       = HMAC(PIN_KEY,   pin_bytes   || "pin")

Earlier fixes retained:
  FIX B (P3/P6): PIN_HMAC replaces raw HSM_PIN.
  FIX D (P4):    extern in .h, definitions in .c — no per-TU duplication.

Usage:
    python3 secrets_to_c_header.py <secrets_json> <hsm_pin> <permissions> [--out-dir DIR]

    secrets_json  Path to JSON file from gen_secrets.py.
    hsm_pin       6 lowercase hex characters (e.g., 1a2b3c).
    permissions   Colon-separated list, e.g. "1234=RWC:aabb=R--".
    --out-dir     Directory for secrets.h (default: ./inc/).
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
    group_id: int  = None
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
    """HMAC(key, data || domain) — matches firmware hmac_sha256()."""
    return hmac_mod.new(key, data + domain, hashlib.sha256).digest()


def compute_permission_mac(perm_key: bytes, permissions: PermissionList) -> bytes:
    """HMAC(PERM_KEY, perm_count || permissions || 'permission').
    PERM_KEY is build-time only and not emitted to firmware.
    """
    perm_count = len(permissions)
    data = struct.pack('B', perm_count) + permissions.to_bytes()
    return compute_hmac(perm_key, data, b'permission')


def compute_pin_hmac(pin_key: bytes, hsm_pin: str) -> bytes:
    """HMAC(PIN_KEY, pin_bytes || 'pin').
    pin_bytes is the raw ASCII of the 6-character hex PIN string.
    """
    pin_bytes = hsm_pin.encode('ascii')
    return compute_hmac(pin_key, pin_bytes, b'pin')


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
    """Generate secrets.h and secrets.c from deployment secrets JSON."""
    raw = json.loads(secrets.decode())

    storage_key       = bytes.fromhex(raw['storage_key'])
    transfer_key      = bytes.fromhex(raw['transfer_key'])
    transfer_auth_key = bytes.fromhex(raw['transfer_auth_key'])
    perm_key          = bytes.fromhex(raw['perm_key'])    # build-time only, not emitted
    pin_key           = bytes.fromhex(raw['pin_key'])     # runtime key, emitted

    perm_count     = len(permissions)
    permission_mac = compute_permission_mac(perm_key, permissions)
    pin_hmac       = compute_pin_hmac(pin_key, hsm_pin)

    # ------------------------------------------------------------------ #
    # secrets.h — extern const declarations                               #
    # ------------------------------------------------------------------ #
    header_path = os.path.join(inc_dir, 'secrets.h')
    with open(header_path, 'w') as f:
        f.write('/**\n')
        f.write(' * @file secrets.h\n')
        f.write(' * @brief HSM deployment secrets — extern declarations (auto-generated)\n')
        f.write(' * @warning DO NOT COMMIT TO VERSION CONTROL\n')
        f.write(' *\n')
        f.write(' * Key split:\n')
        f.write(' *   STORAGE_KEY       — AES-256-GCM for files at rest.\n')
        f.write(' *   TRANSFER_KEY      — AES-256-GCM for files in transit.\n')
        f.write(' *   TRANSFER_AUTH_KEY — HMAC for protocol auth (challenge-response).\n')
        f.write(' *   PIN_KEY           — HMAC for PIN verification (runtime key).\n')
        f.write(' *   PERM_KEY (absent) — Used at build time for PERMISSION_MAC only.\n')
        f.write(' *\n')
        f.write(' * FIX B: PIN_HMAC replaces raw HSM_PIN.\n')
        f.write(' * FIX D: extern const declarations only; definitions in secrets.c.\n')
        f.write(' */\n\n')
        f.write('#ifndef __SECRETS_H__\n')
        f.write('#define __SECRETS_H__\n\n')
        f.write('#include "security.h"\n')
        f.write('#include <stdint.h>\n\n')
        f.write(f'#define PERM_COUNT {perm_count}\n\n')
        f.write('/* AES-256-GCM key for files at rest (4-byte aligned for AESADV). */\n')
        f.write('extern const uint8_t STORAGE_KEY[32];\n\n')
        f.write('/* AES-256-GCM key for files in transit. */\n')
        f.write('extern const uint8_t TRANSFER_KEY[32];\n\n')
        f.write('/* HMAC-SHA256 key for protocol challenge-response and permission MAC verify. */\n')
        f.write('extern const uint8_t TRANSFER_AUTH_KEY[32];\n\n')
        f.write('/* HMAC-SHA256 key for PIN verification (separate from TRANSFER_AUTH_KEY). */\n')
        f.write('extern const uint8_t PIN_KEY[32];\n\n')
        f.write('/* HMAC(PIN_KEY, pin_bytes || "pin"). FIX B: replaces raw HSM_PIN. */\n')
        f.write('extern const uint8_t PIN_HMAC[32];\n\n')
        f.write('/* HMAC(PERM_KEY, perm_count || permissions || "permission"). PERM_KEY not in firmware. */\n')
        f.write('extern const uint8_t PERMISSION_MAC[32];\n\n')
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
        f.write(' * PERM_KEY is build-time-only; it is not defined here.\n')
        f.write(' * PIN_KEY is a runtime key stored here — separate from TRANSFER_AUTH_KEY.\n')
        f.write(' * FIX B: PIN_HMAC = HMAC(PIN_KEY, pin_bytes || "pin").\n')
        f.write(' * FIX D: single definition site; secrets.h has only extern decls.\n')
        f.write(' */\n\n')
        f.write('#include "secrets.h"\n\n')

        f.write('/* AES-256-GCM key for files at rest (4-byte aligned for AESADV). */\n')
        f.write('const uint8_t STORAGE_KEY[32] __attribute__((aligned(4))) = {\n')
        f.write(bytes_to_c_array(storage_key))
        f.write('\n};\n\n')

        f.write('/* AES-256-GCM key for files in transit. */\n')
        f.write('const uint8_t TRANSFER_KEY[32] __attribute__((aligned(4))) = {\n')
        f.write(bytes_to_c_array(transfer_key))
        f.write('\n};\n\n')

        f.write('/* HMAC-SHA256 key for protocol challenge-response and permission MAC verify. */\n')
        f.write('const uint8_t TRANSFER_AUTH_KEY[32] = {\n')
        f.write(bytes_to_c_array(transfer_auth_key))
        f.write('\n};\n\n')

        f.write('/* HMAC-SHA256 key for PIN verification (runtime; separate from TRANSFER_AUTH_KEY). */\n')
        f.write('const uint8_t PIN_KEY[32] = {\n')
        f.write(bytes_to_c_array(pin_key))
        f.write('\n};\n\n')

        f.write('/* HMAC(PIN_KEY, pin_bytes || "pin"). FIX B: replaces raw HSM_PIN. */\n')
        f.write('const uint8_t PIN_HMAC[32] = {\n')
        f.write(bytes_to_c_array(pin_hmac))
        f.write('\n};\n\n')

        f.write('/* HMAC(PERM_KEY, perm_count || permissions || "permission"). */\n')
        f.write('const uint8_t PERMISSION_MAC[32] = {\n')
        f.write(bytes_to_c_array(permission_mac))
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
    print(f'  PERM_KEY not written to firmware.')


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

    perms   = PermissionList.deserialize(args.permissions)
    inc_dir = args.out_dir
    src_dir = os.path.join(inc_dir, '..', 'src')

    os.makedirs(inc_dir, exist_ok=True)
    os.makedirs(src_dir, exist_ok=True)

    secrets_to_c_header(perms, inc_dir, src_dir, pin, args.secrets.read())
