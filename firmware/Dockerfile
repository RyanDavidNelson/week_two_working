# Dockerfile for the 2026 eCTF
# Make any changes here to set up your build environment (e.g., installing crypto
# libraries, dependencies, the compiler for a different language)

FROM ubuntu:24.04

LABEL version="0.4"
LABEL description="UTD HSM Docker Container for the 2026 eCTF"

ARG DEBIAN_FRONTEND=noninteractive
WORKDIR /root

# Install requisite packages
RUN apt-get update && apt-get upgrade -y && apt-get install -y \
    python3 \
    python3-pip \
    make \
    wget \
    build-essential \
    unzip

ENV MSPM0_SDK_INSTALL_DIR=/opt/mspm0-sdk-mspm0_sdk_2_06_00_05
ENV TICLANG_ARMCOMPILER=/opt/ti-cgt-armllvm_4.0.3.LTS

# Install MSPM0 SDK
RUN wget https://github.com/TexasInstruments/mspm0-sdk/archive/refs/tags/mspm0_sdk_2_06_00_05.zip && \
    unzip mspm0_sdk_2_06_00_05.zip -d /opt && \
    rm -f -r mspm0_sdk_2_06_00_05.zip ${MSPM0_SDK_INSTALL_DIR}/docs ${MSPM0_SDK_INSTALL_DIR}/examples

# Install TI-Clang for the current machine's architecture
RUN if [ $(uname -m) = "x86_64" ]; then \
    wget -O ti_cgt_armllvm_4.0.3.LTS_linux_installer.bin \
        https://dr-download.ti.com/software-development/ide-configuration-compiler-or-debugger/MD-ayxs93eZNN/4.0.3.LTS/ti_cgt_armllvm_4.0.3.LTS_linux-x64_installer.bin \
        --ca-certificate=SSLCerts/mitre-chain.pem; \
    elif [ $(uname -m) = "aarch64" ] || [ $(uname -m) = "arm64" ]; then \
    wget -O ti_cgt_armllvm_4.0.3.LTS_linux_installer.bin \
        https://dr-download.ti.com/software-development/ide-configuration-compiler-or-debugger/MD-ayxs93eZNN/4.0.3.LTS/ti_cgt_armllvm_4.0.3.LTS_linux-arm64_installer.bin \
        --ca-certificate=SSLCerts/mitre-chain.pem; \
    else \
    $(false); \
    fi && \
    chmod +x ti_cgt_armllvm_4.0.3.LTS_linux_installer.bin && \
    ./ti_cgt_armllvm_4.0.3.LTS_linux_installer.bin --mode unattended --prefix /opt && \
    rm -f ti_cgt_armllvm_4.0.3.LTS_linux_installer.bin

# ---------------------------------------------------------------------------
# Install wolfSSL 5.7.0 (wolfcrypt only — AES-256-GCM + HMAC-SHA256).
#
# IMPORTANT: ./firmware is volume-mounted to /hsm at "docker run" time.
# Anything written to /hsm during the image build is hidden by that mount.
# wolfSSL MUST be installed outside /hsm — we use /opt/wolfssl.
#
# GitHub archive extracts as wolfssl-5.7.0-stable/:
#   wolfssl-5.7.0-stable/wolfssl/wolfcrypt/hmac.h   <- headers
#   wolfssl-5.7.0-stable/wolfcrypt/src/hmac.c       <- sources
#
# After the mv, the Makefile finds them via:
#   CFLAGS  += -I/opt/wolfssl               (resolves <wolfssl/wolfcrypt/hmac.h>)
#   WOLFSSL_SRC = /opt/wolfssl/wolfcrypt/src (source compile rule)
# ---------------------------------------------------------------------------
ENV WOLFSSL_INSTALL_DIR=/opt/wolfssl
RUN wget -O wolfssl.zip \
        https://github.com/wolfSSL/wolfssl/archive/refs/tags/v5.7.0-stable.zip && \
    unzip wolfssl.zip && \
    mv wolfssl-5.7.0-stable ${WOLFSSL_INSTALL_DIR} && \
    rm -f wolfssl.zip

# ---------------------------------------------------------------------------
# Install pyelftools — required by the binary obfuscation scripts.
#
#   scripts/shuffle_sections.py : reads .text.* section names from compiled
#       .so objects to build the shuffled linker script.
#   scripts/fill_gaps.py        : reads the ELF symbol table after linking
#       to locate function boundaries for alignment-gap patching.
#
# Pure-Python; no native deps.
# ---------------------------------------------------------------------------
RUN pip3 install pyelftools --break-system-packages

WORKDIR /hsm

ENTRYPOINT ["bash", "/hsm/build.sh"]
