# Detailed Specifications

Source: https://rules.ectf.mitre.org/2026/specs/detailed_specs.html

# Detailed Specifications[¶](#detailed-specifications "Permalink to this heading")

## Host Tools[¶](#host-tools "Permalink to this heading")

The host tools this year are created by the organizers and read-only.
The host tools create a basic input/output format for communications
between your devices and the host computer. More information on the host
tools is available [here](../system/ectf_tools.html).

## Design Package[¶](#design-package "Permalink to this heading")

The Generate Secrets script must be implemented as a pip-installable Python package
named `ectf26_design`.

### Generate Secrets[¶](#generate-secrets "Permalink to this heading")

Generate Secrets is a function that should be importable using:

```
from ectf26_design.gen_secrets import gen_secrets
```

The function takes a list of groups that will be valid in the system and returns any
secrets that will be passed to future steps.

The full required interface is as follows:

```
def gen_secrets(groups: list[int]) -> bytes:
    pass
```

## HSM Firmware[¶](#hsm-firmware "Permalink to this heading")

There are six required functional elements to the HSM firmware. These
elements directly relate to the host tools:

* List Files
* Read a File from the HSM
* Write a File to the HSM
* Listen for Messages from a Neighboring HSM
* Interrogate Files from a Neighboring HSM
* Receive a File from a Neighboring HSM

All functional requirements must align with the [Timing Requirements](#timing-requirements)

### File Allocation Table[¶](#file-allocation-table "Permalink to this heading")

The File Allocation Table (FAT) is used by the [eCTF Bootloader](../system/bootloader.html) to calculate
cryptographic file digests. It must contain at least 8 of the following 24-byte struct
where each entry corresponds to a file slot. The FAT must be based at the flash address
0x3a000.

FAT[¶](#id3 "Permalink to this table")

| Offset | Size | Name | Description |
| --- | --- | --- | --- |
| 0x0 | 16 | UUID | UUID of the file in that slot |
| 0x10 | 2 | Length | Length of the file |
| 0x12 | 2 | Padding | Unused to pad to 32-bit alignment |
| 0x14 | 4 | Addr | Starting flash address of the file |

### Flash Layout[¶](#flash-layout "Permalink to this heading")

Flash Layout[¶](#id4 "Permalink to this table")

| Offset | Size | Name | Description |
| --- | --- | --- | --- |
| 0x0 | 0x6000 | Bootloader | Reserved for the eCTF bootloader |
| 0x6000 | 0x34000 | APP1 | Flash region that may be used by your design however you see fit. The IVT must be loaded from the base of this region |
| 0x3A000 | 0x400 | File Allocation Table | This page MUST store the [File Allocation Table](#file-allocation-table) |
| 0x3A400 | 0x5c00 | APP2 | Flash region that may be used by your design however you see fit. |

## Detailed Requirements[¶](#detailed-requirements "Permalink to this heading")

The following constraints must be met:

### Permission Strings[¶](#permission-strings "Permalink to this heading")

At build time, a string representing the permission set is provided (e.g.,
`1234=RW-:aabb=RWC:1a2b=--C`).

**Permission list**: The string shall be a colon-separated list of permissions (e.g.,
`<perm1>:<perm2>:<perm3>`).

**Permission entry**: Each entry shall be a pair of group ID and permissions separated
by an equal sign (e.g., `<group_id>=<permission>`).

**Group ID**: The group ID shall be a 16-bit hexadecimal number padded with 0s to be a
total of 4 characters with no preceding ‘0x’ (e.g., `4b1d`).

**Permission**: The permission shall be a 3-character string where present permissions
are represented by their opcode and absent permissions are represented by a ‘-’ (e.g.,
`RWC`, `RW-`, `--C`).

### PINs[¶](#pins "Permalink to this heading")

A PIN shall be exactly 6 lowercase hexadecimal characters (0-9, a-f).

Timing Requirements[¶](#id5 "Permalink to this table")

| Operation | Maximum Time for Completion |
| --- | --- |
| Device Wake | 1 second |
| List Files | 500 milliseconds |
| Read File | 3000 milliseconds |
| Write File | 3000 milliseconds |
| Receive File | 3000 milliseconds |
| Interrogate | 1000 milliseconds |
| Any Operation Where an Invalid PIN is Provided | 5 seconds |

File Size Requirements[¶](#id6 "Permalink to this table")

| Component | Size |
| --- | --- |
| Group ID | 16 bits |
| File UUID | 16 bytes |
| File Name | Max 32 bytes (null-terminated) |
| File Content Size | Max 8192 bytes |

File Storage Requirements[¶](#id7 "Permalink to this table")

|  |  |
| --- | --- |
| File Slots | 8 slots |

Group Count Requirements[¶](#id8 "Permalink to this table")

|  |  |
| --- | --- |
| Min number of supported groups (deployment) | 32 groups |
| Min number of supported groups (HSM) | 8 |

[![../../_images/2026%20Read%20The%20Rules.png](images/specs__detailed_specs__2026_20Read_20The_20Rules.png)](../../_images/2026 Read The Rules.png)

## Allowed Programming Languages[¶](#allowed-programming-languages "Permalink to this heading")

To build the firmware your design, your team may choose to implement your design
in any compatible language. To align with good development practices, you must
not use a language that was specifically chosen to be difficult to understand.

The pre-approved programming languages are: C, C++, and Rust. If you wish to use
a different language, please reach out to the organizers first.

Be aware that if your team decides to use a language which incorporates a panic
handler, your design must still adhere to the [Timing Requirements](#timing-requirements)
and should not enter an infinite loop in response to any normal input.

The [Reference Design](../system/reference_design.html) was created in C, and as such if your
team decides to use another programming language, the Dockerfile must be updated
to allow for the organizers and teams to be able to build and utilize your
design.

