# System Overview

Source: https://rules.ectf.mitre.org/2026/system/index.html

# System Overview[¶](#system-overview "Permalink to this heading")

![../../_images/2026%20eCTF%20High%20Level%20System.png](images/system__index__2026_20eCTF_20High_20Level_20System.png)

Competition Components

* [Reference Design](reference_design.html)
* [eCTF Tools](ectf_tools.html)
* [eCTF Bootloader](bootloader.html)
* [eCTF API](api.html)

## Host Computer[¶](#host-computer "Permalink to this heading")

The host computer is a general-purpose computer (i.e., your laptop or
desktop) used to communicate with the [Hardware Security Module (HSM)](#hsm) over a serial
interface through a number of [eCTF Tools](ectf_tools.html). These tools
will be used to initiate the various functionalities of the HSM
device (see [Functional Requirements](../specs/functional_reqs.html)) and to read back status
messages and data. To simplify the system, all Host Tools communicating
with the device will be written by the organizers.

## Hardware Security Module (HSM)[¶](#hardware-security-module-hsm "Permalink to this heading")

The main focus of your team’s work is on the HSM device. An HSM is a
generic security module that could be utilized as a subcomponent in a larger system.
The primary function of this generic device is to store and transfer design files to
other HSMs. The HSM will communicate to the [Host Computer](#host-computer)
over the [Management Interface](#management-interface). HSMs will communicate with each other over
a separate [Transfer Interface](#transfer-interface).

### Files[¶](#files "Permalink to this heading")

Secure file storage and transfer is the primary function of the HSM that your team will
design. Files have a file name, an associated [Permission Group](#permissions),
a Universally Unique Identifier (UUID), and contents. Files are stored in slots on
the HSM.

### Management Interface[¶](#management-interface "Permalink to this heading")

The management interface is a physical interface that is utilized by a
user to instruct the HSM to perform certain actions. Most actions
initiated from the management interface are protected by a PIN. This
prevents unauthorized users from accessing sensitive files stored on the
HSM. Communication on this interface will follow the protocol defined in
the [Functional Requirements](../specs/functional_reqs.html).

### Transfer Interface[¶](#transfer-interface "Permalink to this heading")

The transfer interface is physically distinct from the management
interface. When prompted by the management interface, two HSMs will use
the transfer interface to communicate files and file metadata between
each other.

### Permission Groups[¶](#permission-groups "Permalink to this heading")

Permission groups are the critical security feature that HSMs rely on to
authenticate one another. Every file belongs to one permission group.
HSMs contain the permission data for groups based on the permissions they
have for that group. For example, HSM A may have the read and receive
permissions for the engineering group, but it does not have the write permission.
At the same time, it could also have the write permission for the telemetry group,
but neither the read nor the receive permission.

#### Receive Permission[¶](#receive-permission "Permalink to this heading")

The receive permission enables HSMs to receive a file from a different
HSM that contains files that belong to the group.

For example, if HSM A has the receive permission for the engineering
data group and HSM B has files that belong to the engineering data
group, HSM A will be able to request those files from HSM B. If A does
not have the permission, B should refuse to transfer the file.

#### Write Permission[¶](#write-permission "Permalink to this heading")

The write permission enables an HSM to generate new files that belong to
a specified permission group. For example, if HSM A has the write
permission for the engineering group, it can create files in the engineering group.

#### Read Permission[¶](#read-permission "Permalink to this heading")

With the read permission, an HSM can return the file contents back to
the user over the [Management Interface](#management-interface).

The mere fact that an HSM is storing a file does not mean that it should
necessarily be able to return the file contents back to an authorized
user. HSMs may contain files that they should not read.

## Development Resources[¶](#development-resources "Permalink to this heading")

Teams will be provided the following resources:

* **3x un-keyed** [MSP-LITO-L2228 Board](../getting_started/mspm0l2228.html)s **(Design Phase Boards)**
  :   + These boards will be used for the development of your design.
        Instructions to run the host tools on a local computer to test the
        entire system using the physical hardware are found in
        [eCTF Tools](ectf_tools.html). These devices will not be able to run
        [Attack Phase](../../about/index.html#attack-phase) designs provisioned by the eCTF organizers.
        However, the development microcontrollers can be used to practice
        attacks against designs in the Attack Phase that are compiled
        locally by the team from source.
* **3x keyed** [MSP-LITO-L2228 Board](../getting_started/mspm0l2228.html)s **(Attack Phase Boards)**
  :   + Boxes have small colored stickers to indicate that they contain
        provisioned attack boards
      + These boards will be used for the Attack Phase to securely the
        load other teams’ designs that will be provided by the eCTF
        organizers. These devices are configured for use in the Attack
        Phase and therefore will be unusable during the Design Phase.
* **4x XDS110-ETP-EVM USB Debuggers**
  :   + Used to program, communicate with, and debug the
        [MSP-LITO-L2228 Board](../getting_started/mspm0l2228.html)
* **20x 6” Female/Female Jumper Wires**
  :   + Used for connecting the debugger to the [MSP-LITO-L2228 Board](../getting_started/mspm0l2228.html) and
        for connecting the UART between two HSMs
      + Your team has enough to get started, but the connectors on these wires wear out
        pretty quickly from frequent plugging and un-plugging. You may want to consider
        purchasing some more (e.g. from here: <https://www.adafruit.com/product/1950>).

