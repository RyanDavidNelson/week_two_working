MSPM0_SDK_INSTALL_DIR ?= $(abspath ../../../../../..)

include $(MSPM0_SDK_INSTALL_DIR)/tools/imports_mak/imports.mak.linux

CC      = "$(TICLANG_ARMCOMPILER)/bin/tiarmclang"
LNK     = "$(TICLANG_ARMCOMPILER)/bin/tiarmclang"
OBJCOPY = "$(TICLANG_ARMCOMPILER)/bin/tiarmobjcopy"
BUILDDIR   ?= /tmp/build
VPATH      = "src"
LINKERFILE = "firmware.ld"

# =============================================================================
# Main firmware objects
# =============================================================================
OBJECTS = $(BUILDDIR)/HSM.so \
    $(BUILDDIR)/simple_uart.so \
    $(BUILDDIR)/ti_msp_dl_config.so \
    $(BUILDDIR)/startup_mspm0l222x_ticlang.so \
    $(BUILDDIR)/simple_flash.so \
    $(BUILDDIR)/host_messaging.so \
    $(BUILDDIR)/security.so \
    $(BUILDDIR)/filesystem.so \
    $(BUILDDIR)/commands.so \
    $(BUILDDIR)/crypto.so \
    $(BUILDDIR)/secrets.so

# =============================================================================
# WolfSSL configuration — wolfcrypt only, AES-256-GCM + HMAC-SHA256
#
# wolfSSL lives at /opt/wolfssl inside the Docker image (baked in during
# "docker build").  It cannot be at ./wolfssl because the firmware directory
# is volume-mounted to /hsm at "docker run" time.
#
# Settings strategy:
#   -DWOLFSSL_USER_SETTINGS causes settings.h to include user_settings.h
#   which carries the full configuration.  The three AES-GCM flags are also
#   set on the CFLAGS line so every translation unit sees them regardless of
#   include order.  user_settings.h uses #ifndef guards so the CFLAGS values
#   take precedence and no -Wmacro-redefined warning fires.
#
# Three GCM flags are required — all must be set:
#   WOLFSSL_AES_GCM : top-level enable, processed early by settings.h
#   HAVE_AES_GCM   : public API gate, controls prototypes in aes.h
#   HAVE_AESGCM    : internal compilation gate, controls function bodies
#                    in aes.c — this is the gate that was missing and caused
#                    wc_AesGcmSetKey/Encrypt/Decrypt to be absent from aes.so
#
# NO_AES_CBC intentionally absent:
#   In wolfssl 5.7.0, the AES lookup tables (Te[], Td[]) and GetTable() are
#   compiled under the CBC code path.  GCM's internal AES block encrypt calls
#   into that same table path.  Setting NO_AES_CBC excluded the tables,
#   which excluded GCM, producing the unresolved symbol link error.
#   CBC is compiled in but never called; the flash cost is acceptable.
# =============================================================================

WOLFSSL_INSTALL_DIR = /opt/wolfssl
WOLFSSL_SRC         = $(WOLFSSL_INSTALL_DIR)/wolfcrypt/src

# wolfSSL compiled objects
OBJECTS += $(BUILDDIR)/sha256.so \
           $(BUILDDIR)/hmac.so \
           $(BUILDDIR)/hash.so \
           $(BUILDDIR)/memory.so \
           $(BUILDDIR)/wc_port.so \
           $(BUILDDIR)/aes.so

# Activate user_settings.h for all translation units
CFLAGS += -DWOLFSSL_USER_SETTINGS

# All three GCM gates on the command line — ensures every TU sees them
# before any wolfssl conditional chain runs.  user_settings.h #ifndef guards
# prevent redefinition warnings.
CFLAGS += -DWOLFSSL_AES_GCM
CFLAGS += -DHAVE_AES_GCM
CFLAGS += -DHAVE_AESGCM

# wolfSSL include path
CFLAGS += -I$(WOLFSSL_INSTALL_DIR)

# =============================================================================
# Compiler flags
# =============================================================================
NAME = hsm

CFLAGS += -I.. \
    -D__MSPM0L2228__ \
    -O0 \
    "-I$(MSPM0_SDK_INSTALL_DIR)/source/third_party/CMSIS/Core/Include" \
    "-I$(MSPM0_SDK_INSTALL_DIR)/source" \
    "-I./inc" \
    -gdwarf-3 \
    -mcpu=cortex-m0plus \
    -march=thumbv6m \
    -mfloat-abi=soft \
    -mthumb \
    -fstack-protector-strong

# -fstack-protector-strong: instrument every function that has a local array,
# an address-taken local, or a local struct/union — the realistic smash surface.
# The compiler inserts a load of __stack_chk_guard at entry and a matching
# check at exit; mismatch calls __stack_chk_fail(), which invokes security_halt().
# __stack_chk_guard is defined in security.c and seeded from TRNG in init().
# wolfSSL objects are compiled separately below and do NOT receive this flag —
# wolfcrypt internals are not attack-facing and the overhead is unnecessary.

# =============================================================================
# Linker flags
# =============================================================================
LFLAGS += "-l$(MSPM0_SDK_INSTALL_DIR)/source/ti/drivers/lib/ticlang/m0p/drivers_mspm0l122x_l222x.a" \
    "-l$(MSPM0_SDK_INSTALL_DIR)/kernel/nortos/lib/ticlang/m0p/nortos_mspm0l122x_l222x.a" \
    "-l$(MSPM0_SDK_INSTALL_DIR)/source/ti/driverlib/lib/ticlang/m0p/mspm0l122x_l222x/driverlib.a" \
    "-L$(MSPM0_SDK_INSTALL_DIR)/source" \
    -L.. \
    ./$(LINKERFILE) \
    "-Wl,-m,$(BUILDDIR)/$(NAME).map" \
    -Wl,--rom_model \
    -Wl,--warn_sections \
    "-L$(TICLANG_ARMCOMPILER)/lib" \
    -llibc.a

# =============================================================================
# Build rules
# =============================================================================
all: $(BUILDDIR)/$(NAME).elf $(BUILDDIR)/$(NAME).bin

$(BUILDDIR):
	@ mkdir -p $(BUILDDIR)

# Firmware source files (src/*.c) → BUILDDIR
$(BUILDDIR)/%.so: ./src/%.c | $(BUILDDIR)
	@ echo Building $@
	@ $(CC) $(CFLAGS) -c $< -o $@

# wolfSSL source files → BUILDDIR
# Compiled without -fstack-protector-strong: wolfcrypt is not attack-facing
# and the flag would pull in libssp symbols not available on this bare-metal target.
$(BUILDDIR)/%.so: $(WOLFSSL_SRC)/%.c | $(BUILDDIR)
	@ echo Building WolfSSL: $@
	@ $(CC) $(CFLAGS) -fno-stack-protector -O2 -c $< -o $@

$(BUILDDIR)/$(NAME).elf: $(OBJECTS)
	@ echo Linking $@
	@ $(LNK) -Wl,-u,_c_int00 $(OBJECTS) $(LFLAGS) -o $@

$(BUILDDIR)/$(NAME).bin: $(BUILDDIR)/$(NAME).elf
	@ $(OBJCOPY) -O binary $< $@

clean:
	@ rm -rf $(BUILDDIR)

.PHONY: all clean
