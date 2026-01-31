# Debugger Flag

Source: https://rules.ectf.mitre.org/2026/flags/debugger_flag.html

# Debugger Flag[¶](#debugger-flag "Permalink to this heading")

## Download Challenge Files[¶](#download-challenge-files "Permalink to this heading")

[`Download the GDB challenge binary here: gdb_challenge.bin`](../../_downloads/52a615d73557e8517b2153faa24262a6/gdb_challenge_26.bin)

[`Download the GDB challenge elf here: gdb_challenge.elf`](../../_downloads/20a8c356ff46b87c3e9b28b09f160ae4/gdb_challenge_26.elf)

Once downloaded, update the firmware running on one of your boards using the flash tool.

```
uvx ectf hw <DEVICE_PORT> flash <PATH_TO_CHALLENGE_IMG> -n GDBIMG
```

Follow the instructions to get starting debugging with OpenOCD and GDB here:
[OpenOCD](../getting_started/openocd.html).

Finally, the GDB challenge firmware will print a flag to the UART0 port if
you succeed, so you’ll need a way to read from the serial debug port to get the flag.

## Getting Your Bearings[¶](#getting-your-bearings "Permalink to this heading")

When the device finishes starting up, you should see output along the lines of:
“Welcome to the GDB challenge” printed to the serial console.

After starting an OpenOCD session and connecting to GDB, you should see an output
similar to:

```
(gdb) target remote localhost:3333
Remote debugging using localhost:3333
0x00006f26 in DL_Common_delayCycles (cycles=4000000)
at bazel-out/k8-opt/bin/source/ti/driverlib/dl_common.c:49
warning: 49     bazel-out/k8-opt/bin/source/ti/driverlib/dl_common.c: No such file or directory
(gdb)
```

You are now using GDB. The CPU should have halted once the debugger was connected
and we’re now ready to start debugging!

## Setting a Breakpoint[¶](#setting-a-breakpoint "Permalink to this heading")

Now that we have control of the system, let’s continue to main. To do that, we must
first set a hardware breakpoint using hbreak or hb for shorthand:

To get to the start of the challenge function, set a breakpoint at the
gdb\_challenge use \*gdb\_challenge to get to the start of the function (because \* tells gdb get this address and if you pass it a function it jumps right to the code the user made) function and run to it using `continue` or `c`:

```
(gdb) hb *gdb_challenge
Breakpoint 1 at 0x6750: file src/HSM.c, line 95.
Note: automatically using hardware breakpoints for read-only addresses.
(gdb) c
Continuing.
Thread 2 "max32xxx.cpu" hit Breakpoint 1, gdb_challenge () at src/debugger_challenge.c:102
102 void __attribute__((optimize("O0"))) gdb_challenge() {
```

Now you are stopped at the beginning of the gdb\_challenge function.
Let’s view the current register values with `info registers`:

```
(gdb) info registers
r0             0xdeadbeef          -559038737
r1             0xfeedface          -17958194
r2             0xcafecafe          -889271554
r3             0xc0ff3311          -1057017071
r4             0x3d0900            4000000
r5             0x6fdb              28635
r6             0x5a5a5a5a          1515870810
r7             0xffffffff          -1
r8             0xffffffff          -1
r9             0xffffffff          -1
r10            0xffffffff          -1
r11            0xffffffff          -1
r12            0xffffffff          -1
sp             0x20207fd8          0x20207fd8
lr             0x654b              25931
pc             0x6750              0x6750 <gdb_challenge+12>
xpsr           0x81000000          -2130706432
msp            0x20207fd8          0x20207fd8
psp            0xfffffffc          0xfffffffc
primask        0x0                 0
basepri        0x0                 0
faultmask      0x0                 0
control        0x0                 0
```

We can also view values in memory with `x` specified by address or symbol:

```
(gdb) x gdb_challenge
0x6744 <gdb_challenge>: 0xb082b510
(gdb) x 0x6744
0x6744 <gdb_challenge>: 0xb082b510
```

**Write down the raw 4-byte value of the instruction(s) in memory at `to\_hex` for later
as value1**

Use what you’ve learned so far to set a breakpoint at the start of the `do_some_math`
function.

**Write down the raw value of the stack pointer (SP) after hitting this new breakpoint as value2.
Hint: It should end with 0xb0.**

## Stepping Through Code[¶](#stepping-through-code "Permalink to this heading")

With execution paused at the breakpoint for `do_some_math`, let’s inspect the disassembly
for the function using `disass`

```
(gdb) disass
Dump of assembler code for function do_some_math:
=> 0x00006c9e <+0>:     push    {r4, r5, r6, r7, lr}
   0x00006ca0 <+2>:     sub     sp, #20
   0x00006ca2 <+4>:     str     r0, [sp, #16]
   0x00006ca4 <+6>:     str     r1, [sp, #12]
   0x00006ca6 <+8>:     str     r2, [sp, #8]
   0x00006ca8 <+10>:    str     r3, [sp, #4]
   0x00006caa <+12>:    ldr     r4, [sp, #16]
   0x00006cac <+14>:    ldr     r5, [sp, #12]
   0x00006cae <+16>:    adds    r7, r4, r5
   0x00006cb0 <+18>:    ldr     r1, [sp, #8]
   0x00006cb2 <+20>:    mov     r0, r5
   0x00006cb4 <+22>:    bl      0x69d8 <__aeabi_idivmod>
   0x00006cb8 <+26>:    mov     r6, r0
   0x00006cba <+28>:    muls    r6, r7
   0x00006cbc <+30>:    ldr     r7, [sp, #4]
   0x00006cbe <+32>:    mov     r0, r7
   0x00006cc0 <+34>:    mov     r1, r4
   0x00006cc2 <+36>:    bl      0x69d8 <__aeabi_idivmod>
   0x00006cc6 <+40>:    mov     r0, r1
   0x00006cc8 <+42>:    muls    r0, r6
   0x00006cca <+44>:    eors    r4, r5
   0x00006ccc <+46>:    adds    r1, r7, r4
   0x00006cce <+48>:    bl      0x69d8 <__aeabi_idivmod>
   0x00006cd2 <+52>:    mov     r0, r1
   0x00006cd4 <+54>:    add     sp, #20
   0x00006cd6 <+56>:    pop     {r4, r5, r6, r7, pc}
End of assembler dump.
```

Instead of using breakpoints, we can instead step through this function
instruction by instruction using si for step instruction:

```
(gdb) si
0x00006cac      26      in src/HSM.c
(gdb) si
0x00006cae      26      in src/HSM.c
(gdb) si
0x00006cb0      26      in src/HSM.c
```

You can see that we are stepping through the instructions of the function.
If you run `disass` again, you will see our position has changed:

```
(gdb)disass
Dump of assembler code for function do_some_math:
   0x00006c9e <+0>:     push    {r4, r5, r6, r7, lr}
   0x00006ca0 <+2>:     sub     sp, #20
   0x00006ca2 <+4>:     str     r0, [sp, #16]
=> 0x00006ca4 <+6>:     str     r1, [sp, #12]
   0x00006ca6 <+8>:     str     r2, [sp, #8]
   0x00006ca8 <+10>:    str     r3, [sp, #4]
   0x00006caa <+12>:    ldr     r4, [sp, #16]
   0x00006cac <+14>:    ldr     r5, [sp, #12]
   0x00006cae <+16>:    adds    r7, r4, r5
   0x00006cb0 <+18>:    ldr     r1, [sp, #8]
   0x00006cb2 <+20>:    mov     r0, r5
   0x00006cb4 <+22>:    bl      0x69d8 <__aeabi_idivmod>
   0x00006cb8 <+26>:    mov     r6, r0
   0x00006cba <+28>:    muls    r6, r7
   0x00006cbc <+30>:    ldr     r7, [sp, #4]
   0x00006cbe <+32>:    mov     r0, r7
   0x00006cc0 <+34>:    mov     r1, r4
   0x00006cc2 <+36>:    bl      0x69d8 <__aeabi_idivmod>
   0x00006cc6 <+40>:    mov     r0, r1
   0x00006cc8 <+42>:    muls    r0, r6
   0x00006cca <+44>:    eors    r4, r5
   0x00006ccc <+46>:    adds    r1, r7, r4
   0x00006cce <+48>:    bl      0x69d8 <__aeabi_idivmod>
   0x00006cd2 <+52>:    mov     r0, r1
   0x00006cd4 <+54>:    add     sp, #20
   0x00006cd6 <+56>:    pop     {r4, r5, r6, r7, pc}
End of assembler dump.
```

## Setting a Watchpoint[¶](#setting-a-watchpoint "Permalink to this heading")

Instead of manually stepping through individual instructions, we can also
automatically run through code and break when a variable, register, or value in
memory changes by setting a watchpoint. Let’s set a watchpoint on register `r2`
and continue running:

```
(gdb) watch $r2
Watchpoint 3: $r2
```

By default, GDB will just print the old and new value in signed integer format,
so let’s tell GDB to inspect register `r2` when it breaks on the
watchpoint in order to automatically see the hexadecimal representation:

```
(gdb) commands
Type commands for breakpoint(s) 3, one per line.
End with a line saying just "end".
>info registers r2
>end
```

Now, we can continue running until `r2` changes:

```
(gdb) c
Continuing.

Watchpoint 3: $r2

Old value = -889271554
New value = -8979097
__aeabi_idivmod ()
    at /scratch/build_jenkins/workspace/BuildAndValidate_Worker/llvm_cgt/llvm-project/compiler-rt/lib/builtins/arm/aeabi_idivmod.S:38
warning: 38     /scratch/build_jenkins/workspace/BuildAndValidate_Worker/llvm_cgt/llvm-project/compiler-rt/lib/builtins/arm/aeabi_idivmod.S: No such file or directory
r2             0xff76fd67          -8979097
```

**Continue running through the `do\_some\_math` function until the value of r2
starts with 0xca and record that value as value3**

When we’re done watching `r2`, we can delete the watchpoint. First, view the
existing breakpoints and watchpoints with `info break` or `i b` for shorthand:

```
(gdb) i b
Num     Type           Disp Enb Address    What
1       breakpoint     keep y   0x00006750 in gdb_challenge at src/HSM.c:95
        breakpoint already hit 1 time
2       breakpoint     keep y   0x00006caa in do_some_math at src/HSM.c:26
        breakpoint already hit 1 time
3       watchpoint     keep y              $r2
        breakpoint already hit 6 times
        info registers r2
```

The break number of the `r3` watchpoint is `3`, so we will delete that break
number, and check the break numbers again to make sure we successfully removed
the watchpoint:

```
(gdb) i b
Num     Type           Disp Enb Address    What
1       breakpoint     keep y   0x00006750 in gdb_challenge at src/HSM.c:95
        breakpoint already hit 1 time
2       breakpoint     keep y   0x00006caa in do_some_math at src/HSM.c:26
        breakpoint already hit 1 time
```

## Writing to Registers and Memory[¶](#writing-to-registers-and-memory "Permalink to this heading")

Set a breakpoint at 0x00006cd6 (the end of do\_some\_math) and continue there:

```
(gdb) hb *0x00006cd6
Breakpoint 4 at 0x6cd6: file src/HSM.c, line 26.
(gdb) c
Continuing.

Breakpoint 4, 0x00006cd6 in do_some_math (a=26453, b=-1, c=1515870810, d=28635) at src/HSM.c:26
warning: 26     src/HSM.c: No such file or directory
```

With the set command we can now modify registers (make sure to reset them):

```
(gdb) info registers r0
r0             0x0                 0
(gdb) set $r0=111
(gdb) info registers r0
r0             0x6f                111
(gdb) set $r0=0
```

And memory:

```
(gdb) x 0x2001fff8
0x2001fff8: 0x00000000
(gdb) set *0x2001fff8=0x111
(gdb) x 0x2001fff8
0x2001fff8: 0x00000111
(gdb) set *0x2001fff8=0
```

## Capturing the flag[¶](#capturing-the-flag "Permalink to this heading")

With what you’ve learned, set a breakpoint at the first instruction of the check\_flag
function and continue up to there. Make sure the breakpoint is at the first instruction
in the function and not deeper down.

check\_flag has five arguments; let’s check them out. The ARM calling
convention
is to place the first four arguments in registers (r0-r3) and further arguments
are pushed to the stack.

Print the registers and then the top value on the stack to view the arguments:

```
(gdb) info registers
r0             0x11111111          286331153
r1             0x22222222          572662306
r2             0x33333333          858993459
r3             0x44444444          1145324612
r4             0x6ffa              28666
r5             0x6fdb              28635
r6             0x5a5a5a5a          1515870810
r7             0xffffffff          -1
r8             0xffffffff          -1
r9             0xffffffff          -1
r10            0xffffffff          -1
r11            0xffffffff          -1
r12            0xffffffff          -1
sp             0x20207fd8          0x20207fd8
lr             0x677b              26491
pc             0x6230              0x6230 <check_flag>
xpsr           0x1000000           16777216
msp            0x20207fd8          0x20207fd8
psp            0xfffffffc          0xfffffffc
primask        0x0                 0
basepri        0x0                 0
faultmask      0x0                 0
control        0x0                 0
(gdb) x $sp
0x20207fd8:     0x55555555
```

We can see that arguments 1-4 (0x11111111, 0x22222222, 0x33333333, and
0x44444444) are in registers r0 through r3, and the top value of the stack
hold the fifth argument (0x55555555).
Now, using what you have learned, change the values of the function arguments so
that the first argument is set to value1, the third argument is set to
value2, and the fifth argument is set to value3.

Next, continue program execution and check the serial console output. If you did everything
correctly, you should see a flag, and if not, you should see an explanation of
which argument was incorrect.
If done correctly, When you’re done, type q to quit GDB.

```
(gdb) q
A debugging session is active.

    Inferior 1 [Remote target] will be detached.

Quit anyway? (y or n) y
[Inferior 1 (Remote target) detached]
```

