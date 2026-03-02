"""
gen_secrets.py - Generate deployment secrets for eCTF HSM

Generates five deployment-wide secrets:

  STORAGE_KEY       — AES-256-GCM for files at rest (READ/WRITE).
  TRANSFER_KEY      — AES-256-GCM for files in transit (RECEIVE/LISTEN).
  TRANSFER_AUTH_KEY — HMAC-SHA256 for all protocol challenge-response
                      (sender_auth, receiver_auth, interrogate).
  PERM_MAC_KEY      — HMAC-SHA256 used exclusively at build time to compute
                      PERMISSION_MAC.  This key is NEVER fed into any runtime
                      crypto operation; it only appears in secrets.c as a
                      precomputed constant.  An attacker who recovers
                      TRANSFER_AUTH_KEY via CPA on the handshake traces still
                      cannot forge a PERMISSION_MAC claiming Design RECEIVE
                      because PERM_MAC_KEY is architecturally separate.
  CHALLENGE_TWEAK   — 12-byte deployment-wide mask XOR'd with every nonce
                      before it enters an HMAC call.  Breaks the chosen-input
                      advantage required for CPA: the attacker controls the
                      nonce bytes on the wire but cannot predict the actual
                      HMAC first-block input without knowing CHALLENGE_TWEAK.
                      Both sides use the same tweak (deployment-wide) so
                      mutual authentication still works across devices.

PIN_KEY is intentionally NOT generated here.  It is a per-device secret
generated freshly by secrets_to_c_header.py at Build HSM time so that
extracting PIN_KEY from one device (e.g. Technician, whose PIN is known)
reveals nothing about any other device's PIN.

Author: UTD eCTF Team
Date: 2026

This source file is part of an example system for MITRE's 2026 Embedded CTF
(eCTF). This code is being provided only for educational purposes for the 2026
MITRE eCTF competition, and may not meet MITRE standards for quality. Use this
code at your own risk!

Copyright: Copyright (c) 2026 The MITRE Corporation
"""

import argparse
import json
import secrets as crypto_secrets
from pathlib import Path

from loguru import logger


def gen_secrets(groups: list[int]) -> bytes:
    """Generate the contents of the secrets file.

    This will be passed to the Encoder, ectf26_design.gen_secrets,
    and the build process of the firmware.

    NOTE: you should NOT write to secrets files within this function.
    All generated secrets must be contained in the returned bytes object.

    :param groups: List of permission groups valid in this deployment.
    :returns: Contents of the secrets file (UTF-8 encoded JSON).
    """
    storage_key       = crypto_secrets.token_bytes(32)   # AES-256-GCM at rest
    transfer_key      = crypto_secrets.token_bytes(32)   # AES-256-GCM in transit
    transfer_auth_key = crypto_secrets.token_bytes(32)   # HMAC: handshake auth only
    perm_mac_key      = crypto_secrets.token_bytes(32)   # HMAC: PERMISSION_MAC only
    challenge_tweak   = crypto_secrets.token_bytes(12)   # SCA: nonce XOR mask

    # PIN_KEY is deliberately absent from global secrets.
    # Each Build HSM invocation produces an independent 32-byte PIN_KEY so
    # that devices in the same deployment have unrelated PIN verification keys.

    secrets_dict = {
        "groups":            groups,
        "storage_key":       storage_key.hex(),
        "transfer_key":      transfer_key.hex(),
        "transfer_auth_key": transfer_auth_key.hex(),
        "perm_mac_key":      perm_mac_key.hex(),
        "challenge_tweak":   challenge_tweak.hex(),
    }

    return json.dumps(secrets_dict).encode()


def parse_args():
    """Define and parse the command line arguments."""
    parser = argparse.ArgumentParser(
        description="Generate eCTF deployment secrets."
    )
    parser.add_argument(
        "secrets_file",
        type=Path,
        help="Path to the output secrets file.",
    )
    parser.add_argument(
        "groups",
        nargs="+",
        type=lambda x: int(x, 0),
        help="List of valid permission group IDs (decimal or 0x hex).",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    secrets_data = gen_secrets(args.groups)
    args.secrets_file.write_bytes(secrets_data)
    logger.success(f"Secrets written to {args.secrets_file}")


if __name__ == "__main__":
    main()
