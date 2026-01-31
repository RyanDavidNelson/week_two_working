# Design Phase Flags

Source: https://rules.ectf.mitre.org/2026/flags/design_flags.html

# Design Phase Flags[¶](#design-phase-flags "Permalink to this heading")

## Scenario[¶](#scenario "Permalink to this heading")

ChipCorp Inc. is the world’s largest chip manufacturing entity. [[1]](#id3) Their products are
in everything from children’s toys to water treatment equipment for critical
infrastructure. To maintain their competitive advantage and to protect their customers
from a supply-chain attack, they are in the process of creating a new secure file
storage and transfer system to ensure their proprietary fabrication data does not fall
into the wrong hands, prevent unauthorized modification of key files, and protect their
fabrication infrastructure from tampering.

ChipCorp has contracted your team to help design, create, and test an embedded security
subcomponent of the larger system, a permissioned hardware security module ([HSM](../system/index.html#hsm)). The HSM will have a [Management Interface](../system/index.html#management-interface), over which a user
can list, read, and write files. It will also have a [Transfer Interface](../system/index.html#transfer-interface),
over which two [HSMs](../system/index.html#hsm) can transfer files.

![../../_images/2026%20Interfaces.jpg](images/flags__design_flags__2026_20Interfaces.jpg)

The HSM you design will need to communicate with other pieces of a larger system, so it
is an absolute necessity that you stick with the [Functional Requirements](../specs/functional_reqs.html) laid
out by ChipCorp. They have also provided a set of [Security Requirements](../specs/security_reqs.html) that you
should seek to have your design adhere as closely as possible to. They recognize that
budgets and timelines are not infinite, and they are willing to accept tradeoffs in
order to receive a completed design on time. However, security is what you were
contracted for, so the more secure your system, the better.

## Flags[¶](#flags "Permalink to this heading")

During the [Design Phase](../../about/index.html#design-phase), teams can show that they are staying
on track and earn some points by submitting Design Phase Flags. Teams
will earn full points for submitting flags by the deadline. Flags
submitted after the deadline will earn half points.

| Milestone | Flag Format | Due Date | Points | Description |
| --- | --- | --- | --- | --- |
| Read Rules | `ectf{readtherules_*}` | January 21 | 100 | If you read **all** the rules, you’ll know |
| Boot Reference Design | `ectf{boot_*}` | January 23 | 100 | Provision and boot the [Reference Design](../system/reference_design.html) to receive a flag |
| Design Document | `ectf{designdoc_*}` | January 30 | 100 | Submit an initial [Design Document](design_doc.html) to your team channel |
| Debugger | `ectf{debugger_*}` | February 6 | 100 | Show that you can use a [debugger](debugger_flag.html). |
| Use the Testing Service | `ectf{testing_*}` | February 13 | 100 | Successfully complete a `clone_repo` flow on the [testing service](../handoff/testing_service.html) and read the results. |
| Attack the Reference Design | See: [Attack Phase Flags](attack_flags.html#attack-flags) | February 20 | 100 | Capture flags by attacking a deployment of the [Reference Design](../system/reference_design.html). In order to capture these flags you will need the reference attack package which [`can be downlaoded here: attack_package.enc.`](../../_downloads/3c7d8f7b3cdf87759caac4920c6ad454/attack_package.enc) See [List and Download Attack Packages](../handoff/testing_service.html#download-attack-package-tool) for more details. |
| Final Design Submission | `ectf{handoff_*}` | April 15 | 1,000 | Pass [Handoff](../handoff/index.html) to earn points and enter the [Attack Phase](../../about/index.html#attack-phase) |
| Bug Bounty |  | April 15 | Up to 200 | See [Bug Bounty](#bug-bounty) below |

## Bug Bounty[¶](#bug-bounty "Permalink to this heading")

If your team happens to find a bug in the
[Reference Design](../system/reference_design.html), you can earn points for it! Your
team will receive 100 points for each bug found, and another 100 points if you submit a
corresponding fix. If multiple teams find the same bug, points will be distributed on a
first come, first serve basis.

Sometimes whether an issue is truly a bug (or a feature!) is a matter of opinion
- the eCTF organizers reserve the right to reject bug reports for trivial issues
and combine multiple similar reported bugs into one. Submitted bugs will be
accepted if there is a violation of the functional requirements in the reference
design that prevents it from working correctly under nominal operation.

Submissions for typos or clarifications on documentation provided by the
organizers will not be considered for additional points, although we appreciate
being notified about these mistakes so we can make the appropriate edits and
provide further explanation where it is necessary.

Please submit Bug Bounty requests through your private team channel on
[Zulip](../../about/zulip.html) tagging `@organizers`.

[[1](#id1)]

The scenario presented here is purely fictional and although it parallels
real-world situations, it does not perfectly reflect reality. Any similarity to real
entities or events is purely coincidental.

