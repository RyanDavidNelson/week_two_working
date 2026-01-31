# Attack Phase Flags and Scenarios

Source: https://rules.ectf.mitre.org/2026/flags/attack_flags.html

# Attack Phase Flags and Scenarios[¶](#attack-phase-flags-and-scenarios "Permalink to this heading")

Tip

**Understanding the contents of this page is critical to properly securing your
design**. If something is unclear, please reach out to the organizers on
[Zulip](../../about/zulip.html) to clarify.

## Scenario[¶](#scenario "Permalink to this heading")

ChipCorp has also contracted your team to perform a red team assessment against several
candidate designs for their permissioned file storage and transfer system. In order to
evaluate different designs for adherence to the [Security Requirements](../specs/security_reqs.html) they
created a scenario that accurately reflects their threat model. It has
three components: the Technician HSM, the Engineer HSM, and the Photolithography HSM.

![../../_images/2026%20Attack%20Scenario.jpg](images/flags__attack_flags__2026_20Attack_20Scenario.jpg)

Attack Scenario[¶](#id3 "Permalink to this image")

Each of the names under the “permissions” columns represent a category of [file](../system/index.html#files) type. Each of these categories will be distinguished via a unique group
ID. E.g., both the Engineer and the Photolithography Machine have different
[Permission Groups](../system/index.html#permissions) for files in the design group.

**Technician**: The Technician is responsible for transferring firmware update files to,
pulling telemetry data from, and updating the calibration configuration on the
Photolithography machine. The Technician does not have the permission to receive, write,
or read design files. The attacker will know the pin for this device and will have
complete physical access to it.

**Engineer**: The Engineer is responsible for creating design files that will be sent to
the Photolithography machine for printing. The Engineer’s HSM has the permission to
read, write, and receive files in the design group. The attacker will not know the pin
to this device, but will have unrestricted physical access to it.

**Photolithography Machine**: The Photolithography Machine is responsible for
fabricating the chips based on the design files from the Engineer. It also can receive
firmware updates and calibration data from the Technician, and create telemetry data to
be received by the technician. The attacker will not know the pin to this device and
will only have access to the transfer interface via the
[Remote Scenario](remote_scenario.html).

[![../../_images/Attacker%20Access.jpg](images/flags__attack_flags__Attacker_20Access.jpg)](../../_images/Attacker Access.jpg)

Attacker Initial Access[¶](#id4 "Permalink to this image")

In this imaginary scenario, a rival entity has paid a technician to cause financial harm
to ChipCorp. This is an insider threat. As the red team, you will act as the rogue
technician. With valid access to your own [HSM](../system/index.html#hsm) and its permissions, you
will seek to attack the Engineer and Photolithography HSMs.

There is one attack phase flag associated with each of the five below attack scenarios.
They are designed to test whether the [Security Requirements](../specs/security_reqs.html) are upheld by the
design and capturing a flag is how the attacker can demonstrate that a security
requirement was violated. [[1]](#id2)

### Steal Design[¶](#steal-design "Permalink to this heading")

For the Steal Design flag, your goal is to obtain design files from the engineer that
you are not supposed to have. The flag will be provided when you can Receive a design
file from either the Engineer HSM or the Photolithography HSM to the attacker
(technician) HSM for which you do not have the receive permission.

![../../_images/2026%20Steal%20Design%20Flag.jpg](images/flags__attack_flags__2026_20Steal_20Design_20Flag.jpg)

#### How to Obtain the Steal Design Flag[¶](#how-to-obtain-the-steal-design-flag "Permalink to this heading")

This flag is a bit nonstandard because you will perform the attack locally, but you will
need the remote infrastructure to obtain the flag. You can, at any time, query the
secure bootloader (note: not the insecure bootloader) for a cryptographic digest of any
file on the HSM.

```
$ uvx ectf hw COM10 digest 0
Requesting digest
Submit the following to the API:
    ec11607bcc1e01b698d923c01e01b6c716e36142f646e00938ee8b358865ed21039ee28fe0ff71330ed70f6a5be788dd7df6263e9bdd385903a857e230032ad5
```

Once you successfully get one of the two existing design files onto the Technician HSM,
submit its digest to the testing API using the [correct API endpoint](../system/api.html#steal-design).

### Read Update[¶](#read-update "Permalink to this heading")

For the Read Update flag, your goal is to extract firmware update files to learn how the
Photolithography machine works. The [attacker (technician) HSM](#technician-hsm) has a proprietary update file stored on it for which it has no
read permission. If this file can be read, it contains the flag.

![../../_images/2026%20Read%20Update%20Flag.jpg](images/flags__attack_flags__2026_20Read_20Update_20Flag.jpg)

### Read Design[¶](#read-design "Permalink to this heading")

For the Read Design flag, your goal is to recover proprietary chip design data. Both the
[Engineer HSM](#engineer-hsm) and the [Photolithography
HSM](#photolithography-hsm) contain a design file for which the Technician HSM does
not have the read permission. The contents of both files contain the flag.

![../../_images/2026%20Read%20Design%20Flag.jpg](images/flags__attack_flags__2026_20Read_20Design_20Flag.jpg)

### Compromise Machine[¶](#compromise-machine "Permalink to this heading")

For the Compromise Machine flag, your goal is to break the Photolithography Machine by
pushing a bad firmware update, resulting maintenance costs or worse: permanent damage.
An update must be uploaded to the Photolithography Machine that has been corrupted. The
Photolithography Machine must accept this file as valid, and a flag will be provided.
The contents of the uploaded file do not matter as long as it does not match the update
file in the attack scenario.

![../../_images/2026%20Compromise%20Machine%20Flag.jpg](images/flags__attack_flags__2026_20Compromise_20Machine_20Flag.jpg)

### Backdoored Design[¶](#backdoored-design "Permalink to this heading")

For the Backdoored Design flag, your goal is to insert malicious data into the
fabrication process. An arbitrary design file must be uploaded to the Photolithography
Machine. If the Photolithography Machine accepts this file as valid and it contains the
predetermined “back door”, a flag will be provided.

![../../_images/2026%20Backdoored%20Design%20Flag.jpg](images/flags__attack_flags__2026_20Backdoored_20Design_20Flag.jpg)

## Attack Phase Flags[¶](#attack-phase-flags "Permalink to this heading")

During the Attack Phase, teams will test the security of other teams’ designs by
attempting to capture Attack Phase [Flags](../../glossary.html#term-Flags). Each flag represents proof of
an attacker’s ability to compromise one or more security requirements of a
design.

| Flag | Format | Description |
| --- | --- | --- |
| Steal Design | `ectf{steal_*}` | Receive a file for which you do not have the receive permission |
| Read Update | `ectf{update_*}` | Read a file on your HSM for which you do not have the read permission |
| Read Design | `ectf{design_*}` | Read a design file from a device that you don’t have the PIN for |
| Compromise Machine | `ectf{compromise_*}` | Cause the remote HSM to accept a corrupted update file |
| Backdoored Design | `ectf{backdoor_*}` | Cause the remote HSM to accept a specially-crafted backdoored design |

[[1](#id1)]

The scenario presented here is purely fictional and although it parallels
real-world situations, it does not perfectly reflect reality. Any similarity to real
entities or events is purely coincidental.

