"""
secrets_to_c_header.py - Convert deployment secrets to C header

Generates secrets.h containing:
- GCM_KEY: 256-bit AES-GCM key (4-byte aligned for AESADV)
- AUTH_KEY: 256-bit HMAC-SHA256 key
- HSM_PIN: Device PIN
- PERM_COUNT: Number of permissions
- PERMISSION_MAC: HMAC(AUTH_KEY, perm_count || permissions || "permission")
- global_permissions[]: Permission array

Author: UTD eCTF Team
Date: 2026
Copyright: Copyright (c) 2026 The MITRE Corporation
"""

import os
import json
import hmac
import hashlib
import struct
import argparse
from dataclasses import dataclass


@dataclass
class Permission:
    """Represents a permission for one group."""
    group_id: int = None
    read: bool = False
    write: bool = False
    receive: bool = False

    @classmethod
    def deserialize(cls, perms: str):
        """Create a Permission from "<group_id>=<RWC>" string."""
        group_id, perm_string = perms.split('=')
        return cls(
            int(group_id, 16),
            read=(perm_string[0] == 'R'),
            write=(perm_string[1] == 'W'),
            receive=(perm_string[2] == 'C'),
        )

    def serialize(self) -> str:
        ret = f'{self.group_id:04x}='
        for perm, shorthand in {'read': 'R', 'write': 'W', 'receive': 'C'}.items():
            ret += shorthand if getattr(self, perm) else "-"
        return ret

    def to_bytes(self) -> bytes:
        """Serialize: group_id (2 bytes LE) || read (1) || write (1) || receive (1)."""
        return struct.pack(
            '<HBBB',
            self.group_id,
            1 if self.read else 0,
            1 if self.write else 0,
            1 if self.receive else 0
        )


class PermissionList(list):
    """Set of permissions for an HSM."""

    def __init__(self, *args):
        for item in args:
            if isinstance(item, Permission):
                self.append(item)

    @classmethod
    def deserialize(cls, perms: str):
        """Create from colon-separated string, e.g. "1234=RWC:5678=R--"."""
        ret = cls()
        if not perms:
            return ret
        for entry in perms.split(":"):
            entry = entry.strip()
            if entry:
                ret.append(Permission.deserialize(entry))
        return ret

    def serialize(self) -> str:
        return ':'.join(perm.serialize() for perm in self)

    def to_bytes(self) -> bytes:
        """Serialize all permissions to bytes for HMAC."""
        return b''.join(perm.to_bytes() for perm in self)


def compute_permission_mac(auth_key: bytes, permissions: PermissionList) -> bytes:
    """Compute HMAC-SHA256(AUTH_KEY, perm_count || permissions || "permission").

    Domain separator "permission" appended to match firmware hmac_sha256()
    which always computes HMAC(key, data || domain).
    """
    perm_count = len(permissions)
    data = struct.pack('B', perm_count) + permissions.to_bytes()
    data_with_domain = data + b"permission"
    return hmac.new(auth_key, data_with_domain, hashlib.sha256).digest()


def bytes_to_c_array(data: bytes, per_line: int = 8) -> str:
    """Convert bytes to C array initializer string."""
    lines = []
    for i in range(0, len(data), per_line):
        chunk = data[i:i + per_line]
        hex_values = ', '.join(f'0x{b:02x}' for b in chunk)
        lines.append(f'    {hex_values},')
    return '\n'.join(lines)


def secrets_to_c_header(
    permissions: PermissionList,
    path: str,
    hsm_pin: str,
    secrets: bytes
):
    """Generate secrets.h file."""
    secrets_dict = json.loads(secrets.decode())

    gcm_key = bytes.fromhex(secrets_dict['gcm_key'])
    auth_key = bytes.fromhex(secrets_dict['auth_key'])

    permission_mac = compute_permission_mac(auth_key, permissions)

    with open(os.path.join(path, "secrets.h"), 'w') as f:
        f.write("/**\n")
        f.write(" * @file secrets.h\n")
        f.write(" * @brief HSM deployment secrets (auto-generated)\n")
        f.write(" * @warning DO NOT COMMIT TO VERSION CONTROL\n")
        f.write(" */\n\n")

        f.write("#ifndef __SECRETS_H__\n")
        f.write("#define __SECRETS_H__\n\n")
        f.write('#include "security.h"\n')
        f.write('#include <stdint.h>\n\n')

        # PIN
        f.write(f'#define HSM_PIN "{hsm_pin}"\n\n')

        # Permission count
        f.write(f'#define PERM_COUNT {len(permissions)}\n\n')

        # GCM_KEY — 4-byte aligned for DL_AESADV_setKeyAligned() cast
        f.write("/* AES-256-GCM key (4-byte aligned for AESADV register load) */\n")
        f.write("static const uint8_t GCM_KEY[32] __attribute__((aligned(4))) = {\n")
        f.write(bytes_to_c_array(gcm_key))
        f.write("\n};\n\n")

        # AUTH_KEY
        f.write("/* HMAC-SHA256 key */\n")
        f.write("static const uint8_t AUTH_KEY[32] = {\n")
        f.write(bytes_to_c_array(auth_key))
        f.write("\n};\n\n")

        # PERMISSION_MAC
        f.write('/* HMAC(AUTH_KEY, perm_count || permissions || "permission") */\n')
        f.write("static const uint8_t PERMISSION_MAC[32] = {\n")
        f.write(bytes_to_c_array(permission_mac))
        f.write("\n};\n\n")

        # Permissions array
        f.write("const static group_permission_t global_permissions[MAX_PERMS] = {\n")
        for perm in permissions:
            f.write(
                f"\t{{{hex(perm.group_id)}, "
                f"{str(perm.read).lower()}, "
                f"{str(perm.write).lower()}, "
                f"{str(perm.receive).lower()}}},\n"
            )
        # Pad remaining slots
        for _ in range(len(permissions), 8):
            f.write("\t{0x0000, false, false, false},\n")
        f.write("};\n")

        f.write("\n#endif  /* __SECRETS_H__ */\n")


if __name__ == '__main__':
    def parse_args():
        parser = argparse.ArgumentParser(
            description="Convert deployment secrets to C header"
        )
        parser.add_argument(
            "secrets",
            type=argparse.FileType("rb"),
            help="Path to secrets file"
        )
        parser.add_argument(
            "hsm_pin",
            type=str,
            help="6-character PIN for the HSM"
        )
        parser.add_argument(
            "permissions",
            type=str,
            help='Colon-separated permissions. E.g., "1234=RWC:5678=R--"'
        )
        return parser.parse_args()

    args = parse_args()
    perms = PermissionList.deserialize(args.permissions)
    secrets_to_c_header(perms, './inc/', args.hsm_pin, args.secrets.read())
