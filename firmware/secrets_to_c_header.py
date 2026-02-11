"""
secrets_to_c_header.py - Convert deployment secrets to C header

Generates secrets.h containing:
- GCM_KEY: For KEYSTORE initialization
- AUTH_KEY: For HMAC operations  
- HSM_PIN: Device PIN
- global_permissions[]: Permission array
- PERMISSION_MAC: HMAC(AUTH_KEY, perm_count || permissions)

Author: UTD eCTF Team
Date: 2026

This source file is part of an example system for MITRE's 2026 Embedded CTF
(eCTF). This code is being provided only for educational purposes for the 2026 MITRE
eCTF competition, and may not meet MITRE standards for quality. Use this code at your
own risk!

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
        """Create a Permission object from a string.
        
        Format: "<group_id>=<permission>"
        Example: "1234=RWC" or "5678=R--"
        """
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
        """Serialize permission to bytes for HMAC.
        
        Format: group_id (2 bytes LE) || read (1) || write (1) || receive (1)
        """
        return struct.pack(
            '<HBBB',
            self.group_id,
            1 if self.read else 0,
            1 if self.write else 0,
            1 if self.receive else 0
        )


class PermissionList(list):
    """Represents a set of permissions for an HSM."""
    
    def __init__(self, *args):
        for item in args:
            if isinstance(item, Permission):
                self.append(item)

    @classmethod
    def deserialize(cls, perms: str):
        """Create permission list from colon-separated string.
        
        Example: "1234=RWC:5678=R--:abcd=--C"
        """
        ret = cls()
        if not perms:
            return ret
        
        permissions_strings = perms.split(":")
        for entry in permissions_strings:
            entry = entry.strip()
            if entry:
                perm_obj = Permission.deserialize(entry)
                ret.append(perm_obj)
        return ret

    def serialize(self) -> str:
        return ':'.join(perm.serialize() for perm in self)
    
    def to_bytes(self) -> bytes:
        """Serialize all permissions to bytes for HMAC."""
        return b''.join(perm.to_bytes() for perm in self)


def compute_permission_mac(auth_key: bytes, permissions: PermissionList) -> bytes:
    """Compute PERMISSION_MAC = HMAC-SHA256(AUTH_KEY, perm_count || permissions).
    
    Args:
        auth_key: 32-byte AUTH_KEY
        permissions: List of permissions
        
    Returns:
        32-byte HMAC
    """
    perm_count = len(permissions)
    
    # Build data: perm_count (1 byte) || serialized permissions
    data = struct.pack('B', perm_count) + permissions.to_bytes()
    
    return hmac.new(auth_key, data, hashlib.sha256).digest()


def bytes_to_c_array(data: bytes, per_line: int = 8) -> str:
    """Convert bytes to C array initialization string."""
    lines = []
    for i in range(0, len(data), per_line):
        chunk = data[i:i+per_line]
        hex_values = ', '.join(f'0x{b:02x}' for b in chunk)
        lines.append(f'    {hex_values},')
    
    return '\n'.join(lines)


def secrets_to_c_header(
    permissions: PermissionList,
    path: str,
    hsm_pin: str,
    secrets: bytes
):
    """Generate secrets.h file.
    
    Args:
        permissions: HSM permission list
        path: Output directory
        hsm_pin: 6-character PIN
        secrets: Raw bytes from secrets file (JSON encoded)
    """
    # Parse secrets JSON from bytes
    secrets_dict = json.loads(secrets.decode())
    
    # Parse keys from secrets
    gcm_key = bytes.fromhex(secrets_dict['gcm_key'])
    auth_key = bytes.fromhex(secrets_dict['auth_key'])
    
    # Compute PERMISSION_MAC
    permission_mac = compute_permission_mac(auth_key, permissions)
    
    # Generate header file
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
        
        # GCM_KEY (32 bytes)
        f.write("/* AES-256-GCM key for encryption + integrity */\n")
        f.write("static const uint8_t GCM_KEY[32] = {\n")
        f.write(bytes_to_c_array(gcm_key))
        f.write("\n};\n\n")
        
        # AUTH_KEY (32 bytes)
        f.write("/* HMAC-SHA256 key for authentication */\n")
        f.write("static const uint8_t AUTH_KEY[32] = {\n")
        f.write(bytes_to_c_array(auth_key))
        f.write("\n};\n\n")
        
        # PERMISSION_MAC (32 bytes)
        f.write("/* HMAC(AUTH_KEY, perm_count || permissions) */\n")
        f.write("static const uint8_t PERMISSION_MAC[32] = {\n")
        f.write(bytes_to_c_array(permission_mac))
        f.write("\n};\n\n")
        
        # Permissions array
        f.write("/* HSM permissions (set at build time, immutable at runtime) */\n")
        f.write("const static group_permission_t global_permissions[MAX_PERMS] = {\n")
        
        for perm in permissions:
            f.write(
                f"\t{{{hex(perm.group_id)}, "
                f"{str(perm.read).lower()}, "
                f"{str(perm.write).lower()}, "
                f"{str(perm.receive).lower()}}},\n"
            )
        
        # Pad remaining slots with zeros
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
