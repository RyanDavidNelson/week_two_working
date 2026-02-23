MSPM0_SDK_INSTALL_DIR ?= $(abspath ../../../../../..)

include $(MSPM0_SDK_INSTALL_DIR)/tools/imports_mak/imports.mak.linux

CC = "$(TICLANG_ARMCOMPILER)/bin/tiarmclang"
LNK = "$(TICLANG_ARMCOMPILER)/bin/tiarmclang"
OBJCOPY = "$(TICLANG_ARMCOMPILER)/bin/tiarmobjcopy"
BUILDDIR ?= /tmp/build
VPATH = "src"
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
# WolfSSL Configuration - HMAC-SHA256 only (no TLS)
# =============================================================================
# Core: wolfcrypt only, no TLS stack
CFLAGS += -DWOLFCRYPT_ONLY
CFLAGS += -DNO_WOLFSSL_DIR

# Embedded environment
CFLAGS += -DSINGLE_THREADED
CFLAGS += -DNO_FILESYSTEM
CFLAGS += -DNO_WRITEV
CFLAGS += -DTIME_T_NOT_64BIT

# We handle RNG ourselves via hardware TRNG
CFLAGS += -DNO_DEV_RANDOM
CFLAGS += -DWC_NO_HASHDRBG

# Callbacks (required for bare metal)
CFLAGS += -DHAVE_PK_CALLBACKS
CFLAGS += -DWOLFSSL_USER_IO
CFLAGS += -DWC_NO_DEFAULT_DEVID
CFLAGS += -DNO_CRYPTO_CB

# Disable ALL unused algorithms (we only need SHA256 + HMAC)
CFLAGS += -DNO_MD4
CFLAGS += -DNO_MD5
CFLAGS += -DNO_SHA
CFLAGS += -DNO_SHA384
CFLAGS += -DNO_SHA512
CFLAGS += -DNO_AES
CFLAGS += -DNO_DES3
CFLAGS += -DNO_RSA
CFLAGS += -DNO_DSA
CFLAGS += -DNO_DH
CFLAGS += -DNO_RC4
CFLAGS += -DNO_RABBIT
CFLAGS += -DNO_HC128
CFLAGS += -DNO_PSK
CFLAGS += -DNO_PWDBASED
CFLAGS += -DNO_CODING
CFLAGS += -DNO_ASN
CFLAGS += -DNO_CERTS
CFLAGS += -DNO_SIG_WRAPPER

# WolfSSL include path
CFLAGS += -I./wolfssl

# =============================================================================
# WolfSSL source objects — compiled into BUILDDIR (not the source tree) so
# stale .o files never accumulate in the mounted host volume between builds.
# =============================================================================
WOLFSSL_SRC = wolfssl/wolfcrypt/src
OBJECTS += $(BUILDDIR)/sha256.so \
           $(BUILDDIR)/hmac.so \
           $(BUILDDIR)/hash.so \
           $(BUILDDIR)/memory.so \
           $(BUILDDIR)/wc_port.so

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
    -mthumb

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

# WolfSSL source files → BUILDDIR (separate rule for the wolfssl source path)
$(BUILDDIR)/%.so: $(WOLFSSL_SRC)/%.c | $(BUILDDIR)
	@ echo Building WolfSSL: $@
	@ $(CC) $(CFLAGS) -c $< -o $@

$(BUILDDIR)/$(NAME).elf: $(OBJECTS)
	@ echo Linking $@
	@ $(LNK) -Wl,-u,_c_int00 $(OBJECTS) $(LFLAGS) -o $@

$(BUILDDIR)/$(NAME).bin: $(BUILDDIR)/$(NAME).elf
	@ $(OBJCOPY) -O binary $< $@

clean:
	@ rm -rf $(BUILDDIR)

.PHONY: all clean
