# Security Requirements

Source: https://rules.ectf.mitre.org/2026/specs/security_reqs.html

# Security Requirements[¶](#security-requirements "Permalink to this heading")

This section defines the security requirements of your design. These
properties will not be tested or evaluated during
[Handoff](../handoff/index.html). Instead, other teams will earn points for
identifying and exploiting failures to properly meet these requirements
by capturing [Attack Phase Flags](../flags/attack_flags.html) during the
[Attack Phase](../../about/index.html#attack-phase). Use these requirements to inform your design
process, identifying and protecting critical data and code paths.

Warning

Your design is **NOT** tested for its adherence to Security Requirements
during [Handoff](../handoff/index.html).

**Remember:** This is an *embedded* security competition. When building
your design to address the Security Requirements, there are subtle
attack vectors that apply specifically to embedded designs. Keep these
in mind as you design for the security requirements.

## Security Requirement 1[¶](#security-requirement-1 "Permalink to this heading")

**An attacker should not be able to perform any file action without a
validly provisioned HSM with the permissions to perform that action on
files belonging to that group.**

The attacker should not be able to read files from an HSM without the
read permission. The attacker should not be able to create files without
the write permission. The attacker should not be able to receive files
from other HSMs without the receive permission. The receive permission
also applies to interrogate, meaning that the interrogated device should
only return metadata about files for which the requesting device has the
receive permission.

## Security Requirement 2[¶](#security-requirement-2 "Permalink to this heading")

**No PIN-protected action should be able to be completed by a user without prior
knowledge of the PIN**

This includes confidentiality of the PIN. The HSM should not expose
information about its PIN to any unauthorized user.

## Security Requirement 3[¶](#security-requirement-3 "Permalink to this heading")

**An HSM should not successfully receive any file that was not generated
by another valid HSM with write permissions for that group**

This includes protecting file integrity from being compromised in any
way by an attacker.

