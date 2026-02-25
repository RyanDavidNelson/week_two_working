"""
gen_secrets.py - Generate deployment secrets for eCTF HSM

Generates four 256-bit keys with separated responsibilities:

  STORAGE_KEY       — AES-256-GCM for files at rest (READ/WRITE).
  TRANSFER_KEY      — AES-256-GCM for files in transit (RECEIVE/LISTEN).
  TRANSFER_AUTH_KEY — HMAC-SHA256 for all protocol challenge-response
                      (sender_auth, receiver_auth, interrogate) AND for
                      computing and verifying PERMISSION_MAC.
  PIN_KEY           — HMAC-SHA256 for computing PIN_HMAC at build time.
                      Also stored in firmware so check_pin_cmp() can
                      re-derive PIN_HMAC from a candidate PIN at runtime.

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
    storage_key       = crypto_secrets.token_bytes(32)  # AES-256-GCM at rest
    transfer_key      = crypto_secrets.token_bytes(32)  # AES-256-GCM in transit
    transfer_auth_key = crypto_secrets.token_bytes(32)  # HMAC: protocol auth + PERMISSION_MAC
    pin_key           = crypto_secrets.token_bytes(32)  # HMAC: PIN verification (runtime)

    secrets_dict = {
        "groups":            groups,
        "storage_key":       storage_key.hex(),
        "transfer_key":      transfer_key.hex(),
        "transfer_auth_key": transfer_auth_key.hex(),
        "pin_key":           pin_key.hex(),
    }

    return json.dumps(secrets_dict).encode()


def parse_args():
    """Define and parse the command line arguments."""
    parser = argparse.ArgumentParser(
        description="Generate deployment secrets for eCTF HSM"
    )
    parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="Force creation of secrets file, overwriting existing file",
    )
    parser.add_argument(
        "secrets_file",
        type=Path,
        help="Path to the secrets file to be created",
    )
    parser.add_argument(
        "groups",
        nargs="+",
        type=lambda x: int(x, 0),
        help="Supported group IDs",
    )
    return parser.parse_args()


def main():
    """Main function of gen_secrets.

    You will likely not have to change this function.
    """
    args = parse_args()

    secrets = gen_secrets(args.groups)

    # NOTE: Printing sensitive data is generally not good security practice.
    logger.debug(f"Generated secrets: {secrets}")

    # Open the file, erroring if it exists unless --force is provided.
    with open(args.secrets_file, "wb" if args.force else "xb") as f:
        f.write(secrets)

    logger.success(f"Wrote secrets to {str(args.secrets_file.absolute())}")
    logger.warning("DO NOT COMMIT THIS FILE TO VERSION CONTROL.")


if __name__ == "__main__":
    main()
