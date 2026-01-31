# Getting Started

Source: https://rules.ectf.mitre.org/2026/getting_started/index.html

# Getting Started[¶](#getting-started "Permalink to this heading")

Contents:

* [MSP-LITO-L2228 Board](mspm0l2228.html)
* [Reference Design Boot Walkthrough](boot_reference.html)
* [Docker](docker.html)
* [Machine Setup](machine_setup.html)
* [OpenOCD](openocd.html)

This section of the docs will help with getting your machine set up to compete
in the 2026 eCTF! The purpose of this competition is to help develop your skills
in software, hardware, embedded systems, and security. Don’t worry if some of
these are new to you; the point is to learn!

Tip

We recommend starting with reading [Start Here](../../ectf_guide.html) to
help your team get started off on the right foot.

Your team is responsible for developing the firmware to run on the MSP-LITO-L2228
board. To allow for standardization of builds, firmware compilation
will be done utilizing [Docker](docker.html), a tool that creates reproducible build
environments. Example code for this competition, as well as examples provided
by Texas Instruments, will be provided in C. Your team is welcome to use other
pre-approved languages (see [Allowed Programming Languages](../specs/detailed_specs.html#allowed-languages)). **Any languages
outside of these will require approval from the organizers.**

To get your bearings, we recommend the familiarizing yourself following pages in order:

1. [MSP-LITO-L2228 Board](mspm0l2228.html) - To learn how to connect the hardware components that you will use
2. [eCTF Bootloader](../system/bootloader.html) - To add the insecure bootloader to your development
   boards
3. [Design Phase Flags](../flags/design_flags.html) - To understand the design phase at a high level. You
   don’t have to understand the details immediately.
4. [Attack Phase Flags and Scenarios](../flags/attack_flags.html) - To understand the attack phase at a high level. You
   don’t have to understand the details immediately.
5. [Reference Design Boot Walkthrough](boot_reference.html) - To get started with the reference design

