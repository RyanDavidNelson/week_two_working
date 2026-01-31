# UTD's MITRE eCTF Design

This repository holds UT Dallas's design for the 2026 MITRE eCTF. We are working to secure the insecure example design for an eCTF Hardware Security Module provided by MITRE.

The rules for the 2026 eCTF can be found here: https://rules.ectf.mitre.org/.

## Layout

- `firmware/` - Source code to build the firmware
    - `Makefile` - This makefile is invoked by the eCTF tools when creating an HSM.
    - `Dockerfile` - Describes the build environment used by eCTF build tools.
    - `secrets_to_c_header.py` - Python file to convert from global secrets to firmware-parsable header file
    - `inc/` - Directory with c header files
    - `src/` - Directory with c source files
    - `wolfssl/` - Location to place wolfssl library for included Crypto Example
    - `firmware.ld` - Defines memory layout of built firmware
- `ectf26_design/` - Pip-installable module for generating secrets
    - `src/` - Secrets gen source code
        - `gen_secrets.py` - Generates shared secrets
    - `pyproject.toml` - File that tells pip how to install this module
- `Makefile` - Helper script to simplify repetitive build steps
- 'design_documentation' - Design Document, Timeline, and Task List for Team Organization
