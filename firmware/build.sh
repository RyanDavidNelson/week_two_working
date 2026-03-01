#!/usr/bin/env bash
# build.sh — HSM firmware build with binary obfuscation pipeline.
#
# Pipeline:
#   1. Generate secrets header
#   2. compile_only  — compile all .so objects, no link yet
#   3. shuffle_sections.py — randomise .text.* section order → shuffled .ld
#   4. Link with shuffled linker script
#   5. fill_gaps.py — fill inter-function alignment gaps with Thumb B . decoys
#   6. Strip DWARF and symbol table (--strip-debug then --strip-all)
#   7. Produce flat binary; copy outputs to /out
#
# fill_gaps runs BEFORE stripping because it needs the ELF symbol table to
# locate function boundaries.  Stripping runs AFTER fill_gaps on the patched ELF.

set -euo pipefail

BUILDDIR=${1:-/tmp/build}
SCRIPTS_DIR="/hsm/scripts"
TIARMOBJCOPY="${TICLANG_ARMCOMPILER}/bin/tiarmobjcopy"

# --------------------------------------------------------------------------
# Step 1: Generate secrets header from global secrets + env vars
# --------------------------------------------------------------------------
python3 secrets_to_c_header.py /secrets/global.secrets "${HSM_PIN}" "${PERMISSIONS}"

# --------------------------------------------------------------------------
# Step 2: Compile all objects without linking
# shuffle_sections.py needs the .so files to exist before it can read their
# section names, so we compile first and link second.
# --------------------------------------------------------------------------
make BUILDDIR="${BUILDDIR}" compile_only

# --------------------------------------------------------------------------
# Step 3: Randomise function section layout
# Reads every .so in BUILDDIR, collects .text.<sym> sections, shuffles them
# with os.urandom-backed SystemRandom, and emits firmware_shuffled.ld.
# Every build produces a different function-address map in flash.
# --------------------------------------------------------------------------
SHUFFLED_LD="${BUILDDIR}/firmware_shuffled.ld"

python3 "${SCRIPTS_DIR}/shuffle_sections.py" \
    "${BUILDDIR}" \
    "/hsm/firmware.ld" \
    "${SHUFFLED_LD}"

# --------------------------------------------------------------------------
# Step 4: Link with the shuffled linker script
# LINKERFILE_PATH overrides the Makefile default (./firmware.ld).
# --------------------------------------------------------------------------
make BUILDDIR="${BUILDDIR}" \
     LINKERFILE_PATH="${SHUFFLED_LD}"

# --------------------------------------------------------------------------
# Step 5: Fill inter-function alignment gaps with Thumb B . decoys
# Operates on the freshly linked ELF before any stripping.
# Writes patched ELF to hsm_patched.elf.
#
# B . (0xFE 0xE7) terminates Ghidra/IDA linear-sweep disassembly at each
# alignment gap and may cause the analyser to create false function entries,
# polluting the function list.  On real hardware these bytes are in padding
# and are never reached.
# --------------------------------------------------------------------------
python3 "${SCRIPTS_DIR}/fill_gaps.py" \
    "${BUILDDIR}/hsm.elf" \
    "${BUILDDIR}/hsm_patched.elf"

# --------------------------------------------------------------------------
# Step 6: Strip DWARF debug info and symbol table
#
#   --strip-debug : removes .debug_* sections.  Without DWARF, Ghidra/IDA
#                   lose all struct layouts, local variable names, types,
#                   and file/line mappings.  Every symbol becomes sub_XXXX.
#   --strip-all   : removes .symtab and .strtab.  No function or global
#                   names survive in the binary.
#
# We produce an intermediate hsm_stripped.elf (debug stripped) then
# hsm_final.elf (all symbols stripped).  The unstripped hsm_patched.elf
# stays in BUILDDIR for your own debugging — it is NOT copied to /out.
# --------------------------------------------------------------------------
"${TIARMOBJCOPY}" --strip-debug \
    "${BUILDDIR}/hsm_patched.elf" \
    "${BUILDDIR}/hsm_stripped.elf"

"${TIARMOBJCOPY}" --strip-all \
    "${BUILDDIR}/hsm_stripped.elf" \
    "${BUILDDIR}/hsm_final.elf"

# --------------------------------------------------------------------------
# Step 7: Produce flat binary and copy to /out
# --------------------------------------------------------------------------
"${TIARMOBJCOPY}" -O binary \
    "${BUILDDIR}/hsm_final.elf" \
    "${BUILDDIR}/hsm_final.bin"

cp "${BUILDDIR}/hsm_final.elf" /out/hsm.elf
cp "${BUILDDIR}/hsm_final.bin" /out/hsm.bin

echo "[build] Done."
echo "  /out/hsm.elf  — stripped ELF"
echo "  /out/hsm.bin  — flat binary for flashing"
echo "  ${BUILDDIR}/hsm_patched.elf  — unstripped debug ELF (local only)"
