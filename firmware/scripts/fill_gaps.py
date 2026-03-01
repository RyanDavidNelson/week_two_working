#!/usr/bin/env python3
"""
fill_gaps.py — patch inter-function alignment gaps with Thumb-16 B . decoys.

Called by build.sh after linking, before stripping.

Usage:
    python3 fill_gaps.py <in_elf> <out_elf>

What it does:
  1. Reads the ELF symbol table to find all STT_FUNC symbols in .text
     (the symbol table is still present at this stage — stripping is later).
  2. Sorts them by start address; computes gaps between consecutive functions.
  3. Verifies each gap is zero-filled padding (not live code or data).
  4. Writes repeating Thumb-16  B .  opcodes into each qualifying gap.
  5. Writes the patched ELF to out_elf; file structure is unchanged.

Why B . (branch-to-self):
  Cortex-M0+ only supports Thumb-16/32 instructions.
  B . terminates Ghidra/IDA linear-sweep disassembly at that address.
  Because it looks like valid, reachable code, Ghidra may auto-create
  function entries at the decoy addresses, polluting the function list.
  These bytes are in alignment padding and are never reached at runtime,
  so functionality is completely unaffected.

Thumb-16 B . encoding (Cortex-M0+):
  Instruction:  B <label>  where label == current PC - 4
  Two-stage fetch adds 4 to PC before decoding, so label = cur_addr - 4.
  Signed 11-bit offset field = (label - PC) / 2 = -4/2 = -2 = 0x7FE (11-bit two's complement)
  Full 16-bit opcode: 0b11100_11111111110 = 0xE7FE
  In memory (little-endian): [0xFE, 0xE7]
"""

import sys
import shutil

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
except ImportError:
    sys.exit("[fill_gaps] ERROR: pyelftools not installed. "
             "Run: pip3 install pyelftools --break-system-packages")


# Thumb-16 B . in little-endian byte order.
DECOY_WORD = bytes([0xFE, 0xE7])

# Only patch gaps of at least 2 bytes (minimum Thumb-16 instruction width).
MIN_GAP = 2


def find_text_section(elf):
    """Return the .text ELFSection, or None."""
    for sec in elf.iter_sections():
        if sec.name == '.text':
            return sec
    return None


def load_func_symbols(elf):
    """
    Return a sorted list of (vma_start, size) for all STT_FUNC symbols
    with size > 0.  Strips the Thumb interwork bit from addresses.

    Loop counter sym_i in [0, num_symbols); terminates when sym_i == num_symbols.
    """
    funcs = []

    for sec in elf.iter_sections():
        if not isinstance(sec, SymbolTableSection):
            continue

        num_symbols = sec.num_symbols()
        for sym_i in range(num_symbols):
            sym = sec.get_symbol(sym_i)
            if sym['st_info']['type'] == 'STT_FUNC' and sym['st_size'] > 0:
                # Strip Thumb bit (LSB set on Cortex-M branch targets).
                vma = sym['st_value'] & ~1
                funcs.append((vma, sym['st_size']))

    funcs.sort(key=lambda x: x[0])
    return funcs


def patch_gaps(elf_bytes, text_sec, funcs):
    """
    Fill zero-padded inter-function alignment gaps with DECOY_WORD.

    text_vma_base : VMA of the first byte of .text in the linked image.
    text_file_off : byte offset of .text data within the ELF file.

    Gap safety checks (all must pass before patching):
      1. gap_len >= MIN_GAP
      2. gap lies entirely within .text
      3. every byte in the gap is 0x00 (confirms alignment padding,
         not live code or data that happens to sit between two functions)

    Loop counter gap_i in [0, len(funcs)-1); terminates when exhausted.
    Loop counter byte_i in [0, fill_len, step 2); terminates when exhausted.

    Returns patched bytearray.
    """
    buf = bytearray(elf_bytes)

    text_vma_base = text_sec['sh_addr']
    text_file_off = text_sec['sh_offset']
    text_size     = text_sec['sh_size']

    def vma_to_file(vma):
        """Convert a VMA within .text to its file offset."""
        return text_file_off + (vma - text_vma_base)

    gaps_patched = 0
    num_gaps = len(funcs) - 1

    for gap_i in range(num_gaps):
        cur_vma,  cur_size  = funcs[gap_i]
        next_vma, _         = funcs[gap_i + 1]

        gap_start = cur_vma + cur_size
        gap_end   = next_vma
        gap_len   = gap_end - gap_start

        # Check 1: gap must be wide enough for at least one Thumb instruction.
        if gap_len < MIN_GAP:
            continue

        # Check 2: gap must lie inside .text.
        if gap_start < text_vma_base:
            continue
        if gap_end > text_vma_base + text_size:
            continue

        file_start = vma_to_file(gap_start)

        # Check 3: all bytes must be zero (alignment padding, not live code).
        gap_region = buf[file_start : file_start + gap_len]
        if any(b != 0x00 for b in gap_region):
            continue

        # Fill with repeating B . pairs; round down to even byte count.
        fill_len = gap_len - (gap_len % 2)
        for byte_i in range(0, fill_len, 2):
            buf[file_start + byte_i]     = DECOY_WORD[0]
            buf[file_start + byte_i + 1] = DECOY_WORD[1]

        gaps_patched += 1

    print(f"[fill_gaps] patched {gaps_patched} alignment gaps with Thumb B . decoys.")
    return buf


def main():
    if len(sys.argv) != 3:
        sys.exit(f"Usage: {sys.argv[0]} <in_elf> <out_elf>")

    in_elf_path  = sys.argv[1]
    out_elf_path = sys.argv[2]

    with open(in_elf_path, 'rb') as f:
        raw = f.read()

    # Re-open for pyelftools (needs a file object, not bytes).
    elf = ELFFile(open(in_elf_path, 'rb'))

    # Must have a .text section to patch.
    text_sec = find_text_section(elf)
    if text_sec is None:
        print("[fill_gaps] WARNING: no .text section; skipping gap fill.")
        shutil.copy(in_elf_path, out_elf_path)
        return

    # Must have at least two function symbols to compute a gap.
    funcs = load_func_symbols(elf)
    if len(funcs) < 2:
        print("[fill_gaps] WARNING: fewer than 2 STT_FUNC symbols found "
              "(already stripped?); skipping gap fill.")
        shutil.copy(in_elf_path, out_elf_path)
        return

    patched = patch_gaps(bytearray(raw), text_sec, funcs)

    with open(out_elf_path, 'wb') as f:
        f.write(patched)

    print(f"[fill_gaps] patched ELF written → {out_elf_path}")


if __name__ == '__main__':
    main()
