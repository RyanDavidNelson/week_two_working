# MSP-LITO-L2228 Board

Source: https://rules.ectf.mitre.org/2026/getting_started/mspm0l2228.html

# MSP-LITO-L2228 Board[¶](#msp-lito-l2228-board "Permalink to this heading")

This years development platform is the Texas Instruments MSP-LITO-L2228.

![../../_images/MSP-LITO-L2228-board.png](images/getting_started__mspm0l2228__MSP-LITO-L2228-board.png)

MSPM0L2228 features:

* Arm 32-bit Cortex-M0+ CPU
* Up to 256KB of flash memory
* 32KB SRAM
* High-performance analog peripherals
* Integrated temperature sensor
* Ultra-low power segmented LCD controller

All documentation on the MSPM0L2228 is available at: <https://www.ti.com/product/MSPM0L2228>.

Some documentation to look over is the:

* [MSPM0L2228 Datasheet](https://www.ti.com/lit/gpn/mspm0l2228)
* [MSPM0L2228 User Guide](https://www.ti.com/lit/pdf/slau847)

Some of these, the user guide especially, are very lengthy. Use these as a resource, but
full comprehension is not required.

The MSPM0 SDK (Software Development Kit) for the MSPM0L2228 is
available at: <https://github.com/TexasInstruments/mspm0-sdk>.

Documentation on the SDK is available at: <https://software-dl.ti.com/msp430/esd/MSPM0-SDK/latest/docs/english/driverlib/mspm0l122x_l222x_api_guide/html/modules.html>.

While there are installation instructions for the SDK here, SDK will be installed for the
2026 eCTF utilizing Docker. See the [Docker](docker.html) page for information on this installation.

A good place to start once you have all of the utilities installed is the Examples included
in the SDK!

Note

The MSPM-LITO-2228 is not currently available for commercial purchase, however the
LP-MSPM0L2228 are largely interchangeable if you would like to purchase additional
boards, available at <https://www.ti.com/tool/LP-MSPM0L2228>

## Connecting A Debugger[¶](#connecting-a-debugger "Permalink to this heading")

To connect the XDS110 debugger to the MSP-LITO-L2228, take 8 female-to-female jumper
wires and connect them to the respective headers as pictured. Ensure that the silkscreen
labels of the pins you are connecting match (e.g., 3v3 should connect to 3v3). If you
connect the wrong pins, you risk damaging the board.

[![../../_images/MSP-LITO-L2228-debugger.png](images/getting_started__mspm0l2228__MSP-LITO-L2228-debugger.png)](../../_images/MSP-LITO-L2228-debugger.png)

The USB end of the debugger can then be plugged into your host computer and should be
recognized as a serial device.

## Connecting Two MSPM0L2228 Boards[¶](#connecting-two-mspm0l2228-boards "Permalink to this heading")

This year’s scenario requires two boards to connect to each other and communicate to
exchange files for the [Listen Command](../specs/functional_reqs.html#listen-command), [Interrogate Files Command](../specs/functional_reqs.html#interrogate-command), and
[Receive File Command](../specs/functional_reqs.html#receive-command).

The interface for board-to-board interactions utilizes UART1 on the board, which is
driven on pins PA9 (RX) and PA8 (TX).

To connect the two boards, use the female-to-female connectors that your team was given
to link the appropriate pins on the two boards together, as shown in the image below.

[![../../_images/MSP-LITO-L2228-connected.png](images/getting_started__mspm0l2228__MSP-LITO-L2228-connected.png)](../../_images/MSP-LITO-L2228-connected.png)

Note

In order for UART communications to function correctly, the TX pin (data Transfer)
on each board must be connected to the RX pin (data Read) on the opposite board.
Thus, the connection must be RX->TX and TX->RX (“swapped”) for the communications to
be successful.

Tip

If you are running into issues, ensure that the boards have a shared ground
reference. They likely already do if both are plugged into the same computer, but if
they don’t, then you will likely need to connect a GND pin from each of the boards
to each other.

## MSPM-LITO-2228 Design Files[¶](#mspm-lito-2228-design-files "Permalink to this heading")

These boards were custom designed, manufactured, and donated the eCTF by Texas
Instruments. If you are interested in the schematics, you can find them on Zulip.

[`Download the User Manual here`](../../_downloads/db70155edc310671b232e0143e7af892/MSP-LITO-G3507%20Evaluation%20Module%20User%27s%20Guide.pdf)

Note

The User Manual is for the MSP-LITO-G3507, which is a near-identical board using
a different MCU.

