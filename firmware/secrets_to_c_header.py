"""
secrets_to_c_header.py — Convert deployment secrets to C header + source.

Generates two files:
  secrets.h  — extern const declarations only (no definitions).
  secrets.c  — full const definitions (compiled once, linked once).

Key split (from gen_secrets.py):

  STORAGE_KEY (32 B)       — AES-256-GCM for files at rest.
  TRANSFER_KEY (32 B)      — AES-256-GCM for files in transit.
  TRANSFER_AUTH_KEY (32 B) — HMAC for handshake challenge-response only.
  PERM_MAC_KEY (32 B)      — HMAC used exclusively to sign PERMISSION_MAC
                             at build time.  Never fed into a runtime HMAC
                             call; CPA on handshake traces recovers TAK but
                             not PERM_MAC_KEY — Flag 3 stays architecturally
                             blocked.
  CHALLENGE_TWEAK (12 B)   — Deployment-wide nonce mask.  XOR'd with every
                             handshake/interrogate nonce before it reaches
                             wc_HmacSetKey.  Both devices in an exchange use
                             the same tweak so authentication still works;
                             an attacker who controls the wire nonce cannot
                             predict the HMAC first-block input.

Per-device key (generated HERE, NOT from global.secrets):

  PIN_KEY (32 B) — HMAC for PIN verification.

  PIN_KEY is generated fresh by os.urandom(32) at Build HSM time so that
  every device has an independent PIN_KEY.  Extracting PIN_KEY from the
  Technician (whose PIN is known) reveals nothing about the Engineer or
  Photolithography machine PIN because their PIN_KEY values are unrelated.

Precomputed auth values:
  PERMISSION_MAC = HMAC(PERM_MAC_KEY, perm_count || perms || "permission")
  PIN_HMAC       = HMAC(PIN_KEY, pin_bytes || "pin")
    pin_bytes = hsm_pin.encode('ascii')  (6 ASCII hex chars, e.g. "1a2b3c")

Author: UTD eCTF Team
Date: 2026
Copyright: Copyright (c) 2026 The MITRE Corporation
"""

import os
import re
import json
import hmac as hmac_mod
import hashlib
import struct
import argparse
from dataclasses import dataclass

# Must match firmware MAX_PERMS.
MAX_PERMS = 8

# Must match firmware NONCE_SIZE.
NONCE_SIZE = 12


# ---------------------------------------------------------------------------
# Permission data model
# ---------------------------------------------------------------------------

@dataclass
class Permission:
    group_id: int  = None
    read:     bool = False
    write:    bool = False
    receive:  bool = False

    @classmethod
    def deserialize(cls, perms: str):
        group_id_str, perm_string = perms.split('=')
        return cls(
            int(group_id_str, 16),
            read    = (perm_string[0] == 'R'),
            write   = (perm_string[1] == 'W'),
            receive = (perm_string[2] == 'C'),
        )

    def to_bytes(self) -> bytes:
        return struct.pack('<HBBB',
            self.group_id,
            1 if self.read    else 0,
            1 if self.write   else 0,
            1 if self.receive else 0,
        )

    def to_c_init(self) -> str:
        r = 'true'  if self.read    else 'false'
        w = 'true'  if self.write   else 'false'
        c = 'true'  if self.receive else 'false'
        return f'    {{0x{self.group_id:04x}, {r}, {w}, {c}}},'


class PermissionList(list):
    @classmethod
    def deserialize(cls, perms_str: str):
        result = cls()
        if not perms_str:
            return result
        for entry in perms_str.split(':'):
            entry = entry.strip()
            if entry:
                result.append(Permission.deserialize(entry))
        return result

    def to_bytes(self) -> bytes:
        return b''.join(p.to_bytes() for p in self)


# ---------------------------------------------------------------------------
# Crypto helpers
# ---------------------------------------------------------------------------

def _hmac_sha256(key: bytes, data: bytes, domain: bytes) -> bytes:
    """HMAC(key, data || domain) — matches firmware hmac_sha256() convention."""
    return hmac_mod.new(key, data + domain, hashlib.sha256).digest()


def compute_pin_hmac(pin_key: bytes, hsm_pin: str) -> bytes:
    """HMAC(PIN_KEY, pin_bytes || 'pin').
    pin_bytes = hsm_pin encoded as ASCII (6 chars: e.g. '1a2b3c').
    """
    return _hmac_sha256(pin_key, hsm_pin.encode('ascii'), b'pin')


def compute_permission_mac(perm_mac_key: bytes, permissions: PermissionList) -> bytes:
    """HMAC(PERM_MAC_KEY, perm_count || serialized_perms || 'permission').

    Uses PERM_MAC_KEY, NOT TRANSFER_AUTH_KEY.  PERM_MAC_KEY never enters any
    runtime crypto call — it only exists in flash as a constant.  An attacker
    who recovers TRANSFER_AUTH_KEY via CPA cannot forge PERMISSION_MAC.
    """
    data = struct.pack('B', len(permissions)) + permissions.to_bytes()
    return _hmac_sha256(perm_mac_key, data, b'permission')


# ---------------------------------------------------------------------------
# C output helpers
# ---------------------------------------------------------------------------

def bytes_to_c_array(data: bytes, per_line: int = 8) -> str:
    lines = []
    for i in range(0, len(data), per_line):
        chunk = data[i:i + per_line]
        lines.append('    ' + ', '.join(f'0x{b:02x}' for b in chunk) + ',')
    return '\n'.join(lines)


# ---------------------------------------------------------------------------
# Main generation function
# ---------------------------------------------------------------------------

def secrets_to_c_header(
    permissions: PermissionList,
    inc_dir: str,
    src_dir: str,
    hsm_pin: str,
    secrets_bytes: bytes,
) -> None:
    raw = json.loads(secrets_bytes.decode())

    storage_key       = bytes.fromhex(raw['storage_key'])
    transfer_key      = bytes.fromhex(raw['transfer_key'])
    transfer_auth_key = bytes.fromhex(raw['transfer_auth_key'])
    perm_mac_key      = bytes.fromhex(raw['perm_mac_key'])
    challenge_tweak   = bytes.fromhex(raw['challenge_tweak'])

    if len(challenge_tweak) != NONCE_SIZE:
        raise ValueError(
            f'challenge_tweak must be {NONCE_SIZE} bytes, '
            f'got {len(challenge_tweak)}.'
        )

    # PIN_KEY is generated per-device here, NOT read from global secrets.
    # Each Build HSM invocation produces an independent 32-byte PIN_KEY so
    # that devices in the same deployment have unrelated PIN verification keys.
    pin_key = os.urandom(32)

    perm_count     = len(permissions)
    pin_hmac       = compute_pin_hmac(pin_key, hsm_pin)
    permission_mac = compute_permission_mac(perm_mac_key, permissions)

    os.makedirs(inc_dir, exist_ok=True)
    os.makedirs(src_dir, exist_ok=True)

    # -----------------------------------------------------------------------
    # secrets.h — extern declarations only
    # -----------------------------------------------------------------------
    header_path = os.path.join(inc_dir, 'secrets.h')
    with open(header_path, 'w') as f:
        f.write('/**\n')
        f.write(' * @file secrets.h\n')
        f.write(' * @brief HSM deployment secrets — extern declarations (auto-generated)\n')
        f.write(' * @warning DO NOT COMMIT TO VERSION CONTROL\n')
        f.write(' *\n')
        f.write(' * Key responsibilities:\n')
        f.write(' *   STORAGE_KEY       — AES-256-GCM at rest.\n')
        f.write(' *   TRANSFER_KEY      — AES-256-GCM in transit.\n')
        f.write(' *   TRANSFER_AUTH_KEY — HMAC handshake challenge-response.\n')
        f.write(' *   PERM_MAC_KEY      — HMAC for PERMISSION_MAC only (build-time).\n')
        f.write(' *   CHALLENGE_TWEAK   — nonce XOR mask (breaks chosen-input CPA).\n')
        f.write(' *   PIN_KEY           — per-device HMAC for PIN verification.\n')
        f.write(' */\n\n')
        f.write('#ifndef __SECRETS_H__\n')
        f.write('#define __SECRETS_H__\n\n')
        f.write('#include "security.h"\n')
        f.write('#include <stdint.h>\n\n')
        f.write(f'/* Number of active entries in global_permissions[]. */\n')
        f.write(f'#define PERM_COUNT {perm_count}\n\n')

        f.write('/* AES-256-GCM key for files at rest. */\n')
        f.write('extern const uint8_t STORAGE_KEY[32];\n\n')

        f.write('/* AES-256-GCM key for files in transit. */\n')
        f.write('extern const uint8_t TRANSFER_KEY[32];\n\n')

        f.write('/* HMAC-SHA256 key for handshake challenge-response. */\n')
        f.write('extern const uint8_t TRANSFER_AUTH_KEY[32];\n\n')

        f.write('/* HMAC-SHA256 key for PERMISSION_MAC only — never used at runtime.\n')
        f.write(' * Separate from TRANSFER_AUTH_KEY so CPA on handshake traces\n')
        f.write(' * cannot recover the key that signs PERMISSION_MAC. */\n')
        f.write('extern const uint8_t PERM_MAC_KEY[32];\n\n')

        f.write('/* 12-byte deployment-wide nonce XOR mask.\n')
        f.write(' * XOR\'d with every handshake/interrogate nonce before the HMAC call.\n')
        f.write(' * Breaks chosen-input CPA: attacker controls wire nonce but not\n')
        f.write(' * the actual HMAC first-block input. */\n')
        f.write('extern const uint8_t CHALLENGE_TWEAK[12];\n\n')

        f.write('/* HMAC-SHA256 key for PIN verification — per-device, not in global.secrets. */\n')
        f.write('extern const uint8_t PIN_KEY[32];\n\n')

        f.write('/* HMAC(PIN_KEY, pin_bytes || "pin") — raw PIN is never stored. */\n')
        f.write('extern const uint8_t PIN_HMAC[32];\n\n')

        f.write('/* HMAC(PERM_MAC_KEY, perm_count || perms || "permission"). */\n')
        f.write('extern const uint8_t PERMISSION_MAC[32];\n\n')

        f.write('/* Permission table — PERM_COUNT active entries, remainder zero-padded. */\n')
        f.write('extern const group_permission_t global_permissions[MAX_PERMS];\n\n')
        f.write('#endif  /* __SECRETS_H__ */\n')

    # -----------------------------------------------------------------------
    # secrets.c — full const definitions
    # -----------------------------------------------------------------------
    source_path = os.path.join(src_dir, 'secrets.c')
    with open(source_path, 'w') as f:
        f.write('/**\n')
        f.write(' * @file secrets.c\n')
        f.write(' * @brief HSM deployment secrets — definitions (auto-generated)\n')
        f.write(' * @warning DO NOT COMMIT TO VERSION CONTROL\n')
        f.write(' *\n')
        f.write(' * PERMISSION_MAC = HMAC(PERM_MAC_KEY, perm_count || perms || "permission")\n')
        f.write(' * PIN_HMAC       = HMAC(PIN_KEY, pin_bytes || "pin")\n')
        f.write(' *\n')
        f.write(' * Both values are precomputed at build time by secrets_to_c_header.py.\n')
        f.write(' * The raw PIN never appears in flash.\n')
        f.write(' *\n')
        f.write(' * PERM_MAC_KEY is absent from any runtime crypto call — it only exists\n')
        f.write(' * here as a frozen constant.  CPA traces against the LISTEN/RECEIVE\n')
        f.write(' * interface target TRANSFER_AUTH_KEY, which signs handshake messages;\n')
        f.write(' * recovering it does not compromise PERMISSION_MAC.\n')
        f.write(' *\n')
        f.write(' * CHALLENGE_TWEAK is XOR\'d with every nonce before it enters hmac_sha256().\n')
        f.write(' * Both communicating devices apply the same tweak (deployment-wide) so\n')
        f.write(' * mutual authentication remains consistent.  An attacker who sends\n')
        f.write(' * chosen nonces cannot predict the actual HMAC input at collection time.\n')
        f.write(' *\n')
        f.write(' * PIN_KEY is device-unique (generated by os.urandom in secrets_to_c_header.py).\n')
        f.write(' * It is absent from global.secrets; this file is the only place it exists.\n')
        f.write(' */\n\n')
        f.write('#include "secrets.h"\n\n')

        f.write('/* AES-256-GCM key for files at rest. */\n')
        f.write('const uint8_t STORAGE_KEY[32] = {\n')
        f.write(bytes_to_c_array(storage_key))
        f.write('\n};\n\n')

        f.write('/* AES-256-GCM key for files in transit. */\n')
        f.write('const uint8_t TRANSFER_KEY[32] = {\n')
        f.write(bytes_to_c_array(transfer_key))
        f.write('\n};\n\n')

        f.write('/* HMAC-SHA256 key for handshake challenge-response. */\n')
        f.write('const uint8_t TRANSFER_AUTH_KEY[32] = {\n')
        f.write(bytes_to_c_array(transfer_auth_key))
        f.write('\n};\n\n')

        f.write('/* HMAC-SHA256 key for PERMISSION_MAC — build-time only, no runtime use. */\n')
        f.write('const uint8_t PERM_MAC_KEY[32] = {\n')
        f.write(bytes_to_c_array(perm_mac_key))
        f.write('\n};\n\n')

        f.write('/* 12-byte nonce XOR mask — deployment-wide, breaks chosen-input CPA. */\n')
        f.write('const uint8_t CHALLENGE_TWEAK[12] = {\n')
        f.write(bytes_to_c_array(challenge_tweak))
        f.write('\n};\n\n')

        f.write('/* HMAC-SHA256 key for PIN verification — per-device, generated at build time. */\n')
        f.write('const uint8_t PIN_KEY[32] = {\n')
        f.write(bytes_to_c_array(pin_key))
        f.write('\n};\n\n')

        f.write('/* HMAC(PIN_KEY, pin_bytes || "pin") — raw PIN never stored. */\n')
        f.write('const uint8_t PIN_HMAC[32] = {\n')
        f.write(bytes_to_c_array(pin_hmac))
        f.write('\n};\n\n')

        f.write('/* HMAC(PERM_MAC_KEY, perm_count || perms || "permission"). */\n')
        f.write('const uint8_t PERMISSION_MAC[32] = {\n')
        f.write(bytes_to_c_array(permission_mac))
        f.write('\n};\n\n')

        f.write('/* Permission table.  PERM_COUNT active entries; rest zero-padded. */\n')
        f.write('const group_permission_t global_permissions[MAX_PERMS] = {\n')
        for perm in permissions:
            f.write(perm.to_c_init() + '\n')
        for _ in range(perm_count, MAX_PERMS):
            f.write('    {0x0000, false, false, false},\n')
        f.write('};\n')


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def _parse_args():
    parser = argparse.ArgumentParser(
        description='Convert eCTF deployment secrets JSON to C header + source.'
    )
    parser.add_argument('secrets', type=argparse.FileType('rb'),
                        help='Path to JSON secrets file from gen_secrets.py.')
    parser.add_argument('hsm_pin', type=str,
                        help='6 lowercase hex chars (e.g. 1a2b3c).')
    parser.add_argument('permissions', type=str,
                        help='Colon-separated permissions, e.g. "1234=RWC:aabb=R--".')
    parser.add_argument('--out-dir', default='.',
                        help='Root output directory (default: .).')
    return parser.parse_args()


def _validate_pin(pin: str) -> None:
    """Abort if pin is not exactly 6 lowercase hex characters."""
    if not re.fullmatch(r'[0-9a-f]{6}', pin):
        raise SystemExit(
            f'ERROR: hsm_pin must be exactly 6 lowercase hex characters '
            f'(got "{pin}").'
        )


def main() -> None:
    args = _parse_args()
    _validate_pin(args.hsm_pin)

    permissions = PermissionList.deserialize(args.permissions)
    if len(permissions) > MAX_PERMS:
        raise SystemExit(
            f'ERROR: too many permission entries ({len(permissions)} > {MAX_PERMS}).'
        )

    inc_dir = os.path.join(args.out_dir, 'inc')
    src_dir = os.path.join(args.out_dir, 'src')

    secrets_to_c_header(
        permissions   = permissions,
        inc_dir       = inc_dir,
        src_dir       = src_dir,
        hsm_pin       = args.hsm_pin,
        secrets_bytes = args.secrets.read(),
    )

    print(f'Generated {os.path.join(inc_dir, "secrets.h")}')
    print(f'Generated {os.path.join(src_dir, "secrets.c")}')


if __name__ == '__main__':
    main()
