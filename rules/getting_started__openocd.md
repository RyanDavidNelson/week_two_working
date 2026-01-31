# OpenOCD

Source: https://rules.ectf.mitre.org/2026/getting_started/openocd.html

# OpenOCD[¶](#openocd "Permalink to this heading")

OpenOCD (Open On-Chip Debugger) is an open-source program that provides control of a
target (MSPM0L228 in this case) to to the developer via an interface (XDS110 debugger in
this case) connected to the microcontroller.

## Installation[¶](#installation "Permalink to this heading")

Support for the MSPM0L2228 requires the latest pre-release of OpenOCD:
<https://github.com/openocd-org/openocd/releases/tag/latest>

## Utilization[¶](#utilization "Permalink to this heading")

OpenOCD provides two main interfaces for examining the program running and hardware of
the MSPM0L2228. These interfaces are the OpenOCD command window provided over a TCP
socket and a remote GDB target.

In order to use either target, an OpenOCD session must be opened. This can be done with
the following command.

Initializing an OpenOCD connection[¶](#id1 "Permalink to this code")

```
 openocd -s ./share/openocd/scripts/ -f interface/xds110.cfg -f target/ti/mspm0.cfg -c 'bindto 0.0.0.0; init; halt'
```

The resulting output should look like:

Successful OpenOCD connection[¶](#id2 "Permalink to this code")

```
openocd -s ./share/openocd/scripts/ -f interface/xds110.cfg -f target/ti/mspm0.cfg -c "bindto 0.0.0.0; init; reset; halt"
Open On-Chip Debugger 0.12.0+dev-g1347b69 (2025-06-07-10:27)
Licensed under GNU GPL v2
For bug reports, read
        http://openocd.org/doc/doxygen/bugs.html
Warn : DEPRECATED: auto-selecting transport "swd". Use 'transport select swd' to suppress this message.
Warn : Transport "swd" was already selected
cortex_m reset_config sysresetreq
Warn : An adapter speed is not selected in the init scripts. OpenOCD will try to run the adapter at very low speed (100 kHz).
Warn : To remove this warnings and achieve reasonable communication speed with the target, set "adapter speed" or "jtag_rclk" in the init scripts.
Info : XDS110: connected
Info : XDS110: vid/pid = 0451/bef3
Info : XDS110: firmware version = 3.0.0.36
Info : XDS110: hardware version = 0x0028
Info : XDS110: connected to target via SWD
Info : XDS110: SWCLK set to 2500 kHz
Info : clock speed 100 kHz
Info : SWD DPIDR 0x6ba02477
Info : [mspm0x.cpu] Cortex-M0+ r0p1 processor detected
Info : [mspm0x.cpu] target has 4 breakpoints, 2 watchpoints
Info : [mspm0x.cpu] Examination succeed
Info : [mspm0x.cpu] starting gdb server on 3333
Info : Listening on port 3333 for gdb connections
Warn : [mspm0x.cpu] target was in unknown state when halt was requested
Info : Listening on port 6666 for tcl connections
Info : Listening on port 4444 for telnet connections
```

The OpenOCD command window can be accessed with telnet. To open this session run telnet localhost 4444.
Note that you may need to enable telnet on your host OS before you can use it!

The snippet below shows an example of opening the OpenOCD command window and running the reg command.
The OpenOCD command window is useful for simple debugging operations such as reading back memory,

A full list of OpenOCD commands can be found at: <https://openocd.org/doc-release/html/index.html>.

OpenOCD Command Window with Telnet[¶](#id3 "Permalink to this code")

```
C:\MaximSDK\Tools\OpenOCD\scripts> telnet localhost 4444
Trying ::1...
telnet: connect to address ::1: Connection refused
Trying 127.0.0.1...
Connected to localhost.
Escape character is '^]'.
Open On-Chip Debugger
> reg
===== arm v7m registers
(0) r0 (/32): 0x0048e4ff
(1) r1 (/32): 0xe000e000
(2) r2 (/32): 0x0048e4ff
(3) r3 (/32): 0x00ab8298
(4) r4 (/32): 0x20000004
(5) r5 (/32): 0x00000000
(6) r6 (/32): 0x00000000
(7) r7 (/32): 0x00000000
(8) r8 (/32): 0x00000000
(9) r9 (/32): 0x00000000
(10) r10 (/32): 0x00000000
(11) r11 (/32): 0x00000000
(12) r12 (/32): 0xf4240000
(13) sp (/32): 0x2001ffe0
(14) lr (/32): 0x10001209
(15) pc (/32): 0x1000135a
(16) xPSR (/32): 0x21000000
(17) msp (/32): 0x2001ffe0
(18) psp (/32): 0x00000000
(20) primask (/1): 0x00
(21) basepri (/8): 0x00
(22) faultmask (/1): 0x00
(23) control (/3): 0x00
(42) d0 (/64): 0x0000000000000000
(43) d1 (/64): 0x0000000000000000
(44) d2 (/64): 0x0000000000000000
(45) d3 (/64): 0x0000000000000000
(46) d4 (/64): 0x0000000000000000
(47) d5 (/64): 0x0000000000000000
(48) d6 (/64): 0x0000000000000000
(49) d7 (/64): 0x0000000000000000
(50) d8 (/64): 0x0000000000000000
(51) d9 (/64): 0x0000000000000000
(52) d10 (/64): 0x0000000000000000
(53) d11 (/64): 0x0000000000000000
(54) d12 (/64): 0x0000000000000000
(55) d13 (/64): 0x0000000000000000
(56) d14 (/64): 0x0000000000000000
(57) d15 (/64): 0x0000000000000000
(58) fpscr (/32): 0x00000000
===== Cortex-M DWT registers
```

GDB (GNU Project Debugger) is a utility that can be used for debugging running programs.
GDB can be utilized for both embedded programs and Linux applications.
GDB is able to utilize OpenOCD to provide descriptive debugging of your programs.

GDB is best utilized with program symbols. Symbols tell GDB information about which line
of C code you are executing, and allows you to analyze operation of your programs at a high level.

## Installing GDB[¶](#installing-gdb "Permalink to this heading")

On Ubuntu, you can install GDB with `sudo apt install gdb-multiarch`.

Before starting GDB ensure that you have started an OpenOCD connection on your host OS.
To start GDB, run

Initializing GDB[¶](#id4 "Permalink to this code")

```
gdb-multiarch hsm.elf
GNU gdb (Ubuntu 9.2-0ubuntu1~20.04.1) 9.2
Copyright (C) 2020 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from hsm.elf...
```

Once you are at this point, GDB has loaded the symbols from your program, but if not yet connected
to the OpenOCD session. To connect, use the command target remote localhost:3333.

Attaching GDB to OpenOCD[¶](#id5 "Permalink to this code")

```
(gdb) target remote localhost:3333
Remote debugging using localhost:3333
0x1000efb6 in MXC_Delay (us=500000) at /root/msdk-2024_02/Libraries/CMSIS/../PeriphDrivers/Source/SYS/mxc_delay.c:233
233         while (SysTick->VAL > endtick) {}
(gdb)
```

Now you are good to go with GDB! GDB has lots of commands that you can utilize to control your
programs operation. A good reference for GDB is: <https://users.ece.utexas.edu/~adnan/gdb-refcard.pdf>.

