# ============================================================================
# Makefile Additions for Crypto Module (Week 2)
# ============================================================================
# Add these changes to firmware/Makefile
# ============================================================================

# --------------------------------------------------------------------------
# 1. ADD crypto.so TO OBJECTS LIST
# --------------------------------------------------------------------------
# Find the OBJECTS = ... line and add:
#     $(BUILDDIR)/crypto.so \

# Example:
# OBJECTS = $(BUILDDIR)/HSM.so \
#     $(BUILDDIR)/simple_uart.so \
#     $(BUILDDIR)/ti_msp_dl_config.so \
#     $(BUILDDIR)/startup_mspm0l222x_ticlang.so \
#     $(BUILDDIR)/simple_flash.so \
#     $(BUILDDIR)/host_messaging.so \
#     $(BUILDDIR)/security.so \
#     $(BUILDDIR)/filesystem.so \
#     $(BUILDDIR)/commands.so \
#     $(BUILDDIR)/crypto.so

# --------------------------------------------------------------------------
# 2. REMOVE CRYPTO_EXAMPLE FLAG, ADD PROPER WOLFSSL FLAGS
# --------------------------------------------------------------------------
# Replace:
#     CRYPTO_EXAMPLE = 0
# With proper wolfssl configuration:

# WolfSSL Configuration for HMAC-SHA256
CFLAGS += -DNO_WOLFSSL_DIR
CFLAGS += -DSINGLE_THREADED
CFLAGS += -DHAVE_PK_CALLBACKS
CFLAGS += -DWOLFSSL_USER_IO
CFLAGS += -DNO_WRITEV
CFLAGS += -DTIME_T_NOT_64BIT
CFLAGS += -DNO_FILESYSTEM
CFLAGS += -DNO_DEV_RANDOM
CFLAGS += -DWC_NO_DEFAULT_DEVID
CFLAGS += -DWOLF_CRYPTO_CB

# Enable SHA-256 and HMAC (disable unused algorithms)
CFLAGS += -DNO_MD5
CFLAGS += -DNO_SHA
CFLAGS += -DNO_AES          # We use hardware AESADV, not wolfssl AES
CFLAGS += -DNO_DES3
CFLAGS += -DNO_RSA
CFLAGS += -DNO_DSA
CFLAGS += -DNO_DH
CFLAGS += -DNO_RC4
CFLAGS += -DNO_RABBIT
CFLAGS += -DNO_HC128
CFLAGS += -DNO_PSK
CFLAGS += -DNO_PWDBASED

# Include wolfssl headers
CFLAGS += -I./wolfssl

# --------------------------------------------------------------------------
# 3. ADD WOLFSSL OBJECTS FOR HMAC-SHA256
# --------------------------------------------------------------------------
WOLFSSL_INC = wolfssl/wolfcrypt/src

OBJECTS += $(WOLFSSL_INC)/sha256.o
OBJECTS += $(WOLFSSL_INC)/hmac.o
OBJECTS += $(WOLFSSL_INC)/hash.o
OBJECTS += $(WOLFSSL_INC)/cryptocb.o

# --------------------------------------------------------------------------
# 4. COMPLETE EXAMPLE MAKEFILE
# --------------------------------------------------------------------------
# Here's what the updated Makefile should look like:

# --- BEGIN UPDATED MAKEFILE ---

MSPM0_SDK_INSTALL_DIR ?= $(abspath ../../../../../..)

include $(MSPM0_SDK_INSTALL_DIR)/tools/imports_mak/imports.mak.linux

CC = "$(TICLANG_ARMCOMPILER)/bin/tiarmclang"
LNK = "$(TICLANG_ARMCOMPILER)/bin/tiarmclang"
OBJCOPY = "$(TICLANG_ARMCOMPILER)/bin/tiarmobjcopy"
BUILDDIR ?= /tmp/build
VPATH = "src"
LINKERFILE = "firmware.ld"

# Main firmware objects
OBJECTS = $(BUILDDIR)/HSM.so \
    $(BUILDDIR)/simple_uart.so \
    $(BUILDDIR)/ti_msp_dl_config.so \
    $(BUILDDIR)/startup_mspm0l222x_ticlang.so \
    $(BUILDDIR)/simple_flash.so \
    $(BUILDDIR)/host_messaging.so \
    $(BUILDDIR)/security.so \
    $(BUILDDIR)/filesystem.so \
    $(BUILDDIR)/commands.so \
    $(BUILDDIR)/crypto.so

# WolfSSL Configuration for HMAC-SHA256
CFLAGS += -DNO_WOLFSSL_DIR
CFLAGS += -DSINGLE_THREADED
CFLAGS += -DHAVE_PK_CALLBACKS
CFLAGS += -DWOLFSSL_USER_IO
CFLAGS += -DNO_WRITEV
CFLAGS += -DTIME_T_NOT_64BIT
CFLAGS += -DNO_FILESYSTEM
CFLAGS += -DNO_DEV_RANDOM
CFLAGS += -DWC_NO_DEFAULT_DEVID
CFLAGS += -DWOLF_CRYPTO_CB
CFLAGS += -DNO_MD5
CFLAGS += -DNO_SHA
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
CFLAGS += -I./wolfssl

# WolfSSL objects for HMAC-SHA256
WOLFSSL_INC = wolfssl/wolfcrypt/src
OBJECTS += $(WOLFSSL_INC)/sha256.o
OBJECTS += $(WOLFSSL_INC)/hmac.o
OBJECTS += $(WOLFSSL_INC)/hash.o
OBJECTS += $(WOLFSSL_INC)/cryptocb.o

NAME = hsm

CFLAGS += -I.. \
    -D__MSPM0L2228__ \
    -O2 \
    "-I$(MSPM0_SDK_INSTALL_DIR)/source/third_party/CMSIS/Core/Include" \
    "-I$(MSPM0_SDK_INSTALL_DIR)/source" \
    "-I./inc" \
    -gdwarf-3 \
    -mcpu=cortex-m0plus \
    -march=thumbv6m \
    -mfloat-abi=soft \
    -mthumb

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

all: $(BUILDDIR)/$(NAME).elf $(BUILDDIR)/$(NAME).bin

$(BUILDDIR):
	@ mkdir -p $(BUILDDIR)

$(BUILDDIR)/%.so: ./src/%.c | $(BUILDDIR)
	@ echo Building $@
	@ $(CC) $(CFLAGS) -c $< -o $@

$(BUILDDIR)/$(NAME).elf: $(OBJECTS)
	@ echo Linking $@
	@ $(LNK) -Wl,-O3 $(OBJECTS) $(LFLAGS) -o $@

$(BUILDDIR)/$(NAME).bin: $(BUILDDIR)/$(NAME).elf
	@ $(OBJCOPY) -O binary $< $@

clean:
	@ rm -rf $(BUILDDIR)

.PHONY: all clean

# --- END UPDATED MAKEFILE ---
