#!/usr/bin/env python3
"""
shuffle_sections.py — randomise function layout in the final binary.

Called by build.sh after compilation (compile_only target), before linking.

Usage:
    python3 shuffle_sections.py <builddir> <base_ld> <out_ld>

How it works:
  1. Parse every .so (ELF relocatable) in BUILDDIR with pyelftools.
  2. Collect every .text.<symbol> section that has non-zero size.
     These are produced by -ffunction-sections: one section per function.
  3. Shuffle the collected list with cryptographic randomness (SystemRandom
     is backed by os.urandom on all POSIX platforms).
  4. Emit a copy of base_ld where the .text output section explicitly lists
     all collected input sections in shuffled order, followed by catch-all
     wildcards for any sections not enumerated (e.g. wolfSSL, startup code).

Effect on RE:
  - Every build produces a different function layout in flash.
  - Addresses from one build do not transfer to another HSM binary.
  - An attacker who reverse-engineers one binary cannot reuse that memory
    map against a different HSM in the same deployment.
  - Cross-reference databases and FLIRT signatures built against one layout
    are invalidated against every other.
"""

import os
import sys
import random
import shutil

try:
    from elftools.elf.elffile import ELFFile
except ImportError:
    sys.exit("[shuffle_sections] ERROR: pyelftools not installed. "
             "Run: pip3 install pyelftools --break-system-packages")


def collect_text_sections(builddir):
    """
    Walk builddir, open every file ending in .so, and collect all
    .text.<name> sections with sh_size > 0.

    Returns a list of (abs_path, section_name) tuples.

    Loop counter entry_i in [0, entry_count); terminates when entry_i == entry_count.
    """
    sections = []

    dir_entries = sorted(os.listdir(builddir))   # sorted → deterministic base order
    entry_count = len(dir_entries)

    for entry_i in range(entry_count):
        fname = dir_entries[entry_i]
        if not fname.endswith('.so'):
            continue

        obj_path = os.path.join(builddir, fname)

        try:
            with open(obj_path, 'rb') as f:
                elf = ELFFile(f)

                # Must be a relocatable object, not a shared lib or executable.
                if elf['e_type'] != 'ET_REL':
                    continue

                # Inner loop: iterate sections in this object.
                # No explicit counter needed — iter_sections() is not bounded
                # by an attack surface, just ELF structure.
                for sec in elf.iter_sections():
                    if sec.name.startswith('.text.') and sec['sh_size'] > 0:
                        sections.append((obj_path, sec.name))

        except Exception as ex:
            # Non-ELF or truncated; skip silently so one bad file doesn't
            # abort the whole build.
            print(f"[shuffle_sections] skipping {fname}: {ex}")

    return sections


def build_shuffled_ld(base_ld, out_ld, sections):
    """
    Read base_ld and replace the .text output-section placeholder with an
    explicitly ordered block listing all shuffled input sections, then
    catch-all wildcards at the end for any sections not enumerated.

    The original line in firmware.ld:
        .text   : palign(8) {} > FLASH

    Becomes:
        .text   : palign(8) {
            /path/to/obj.so(.text.funcA)
            /path/to/obj.so(.text.funcB)
            ...
            *(.text)
            *(.text.*)
        } > FLASH

    The TI linker places input sections in the order listed in the command
    file, so this directly controls function layout in flash.

    Loop counter line_i in [0, len(sections)); terminates when exhausted.
    """
    with open(base_ld, 'r') as f:
        base_text = f.read()

    # Build explicit input-section list (TI linker syntax)
    input_lines = []
    for line_i in range(len(sections)):
        obj_path, sec_name = sections[line_i]
        input_lines.append(f'        {obj_path}({sec_name})')

    explicit_block = '\n'.join(input_lines)

    new_text_section = (
        '.text   : palign(8) {\n'
        f'{explicit_block}\n'
        '        *(.text)\n'
        '        *(.text.*)\n'
        '    } > FLASH'
    )

    # This exact string must exist in firmware.ld — fail loudly if not found.
    TARGET = '.text   : palign(8) {} > FLASH'
    if TARGET not in base_text:
        sys.exit(
            f"[shuffle_sections] ERROR: pattern '{TARGET}' not found in {base_ld}.\n"
            "Check that firmware.ld has not been manually edited."
        )

    modified = base_text.replace(TARGET, new_text_section)

    with open(out_ld, 'w') as f:
        f.write(modified)


def main():
    if len(sys.argv) != 4:
        sys.exit(f"Usage: {sys.argv[0]} <builddir> <base_ld> <out_ld>")

    builddir = sys.argv[1]
    base_ld  = sys.argv[2]
    out_ld   = sys.argv[3]

    # Collect all .text.* sections from compiled firmware objects.
    sections = collect_text_sections(builddir)

    if not sections:
        print("[shuffle_sections] WARNING: no .text.* sections found. "
              "Was -ffunction-sections in CFLAGS? "
              "Copying base linker script unchanged.")
        shutil.copy(base_ld, out_ld)
        return

    # Shuffle with cryptographic randomness (os.urandom under the hood).
    rng = random.SystemRandom()
    rng.shuffle(sections)

    build_shuffled_ld(base_ld, out_ld, sections)

    print(f"[shuffle_sections] {len(sections)} function sections shuffled → {out_ld}")


if __name__ == '__main__':
    main()
