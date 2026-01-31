# Handoff

Source: https://rules.ectf.mitre.org/2026/handoff/index.html

# Handoff[¶](#handoff "Permalink to this heading")

Sections

* [Automated Testing Service](testing_service.html)
* [Submission Process](submission_process.html)

Starting [February 25](../schedule/index.html#important-dates), each team may submit their
completed design to the organizers to attempt to proceed to the
[Attack Phase](../../about/index.html#attack-phase). The organizers will then verify that the submission
meets all functional requirements.

Tip

During the [Design Phase](../../about/index.html#design-phase), test your design frequently using the
[Automated Testing Service](testing_service.html) to make sure you haven’t drifted from the
[Functional Requirements](../specs/functional_reqs.html)

Before submitting, each team’s design must have passed testing using the
[Automated Testing Service](testing_service.html). Once their design passes,
teams should update all documentation to its final state to ensure maximum
[Documentation Points](../flags/documentation_points.html) are earned. Only source code and
documentation that are checked into the repository will be considered. When the
design and documentation are in their final states, they may be submitted to the
organizers for the Handoff process.

The details of the Handoff process will be posted on [Zulip](../../about/zulip.html) and
updated here.

Upon receiving a submission, the eCTF organizers will clone and provision the
team’s system via their repository. Then, the organizers will run a sequence of
test cases that validate whether the system meets the
[Functional Requirements](../specs/functional_reqs.html). The eCTF organizers will contact the submitting
team within two business days after the submission indicating whether the system
is accepted or not, determined by passing all functional tests successfully and
conforming to all other rules.

Warning

Handoff does not test your design for [Security Requirements](../specs/security_reqs.html), so make
sure your design meets them before submitting

## Accepted Designs[¶](#accepted-designs "Permalink to this heading")

If a system is accepted, the organizers will inform the team and create a
[handoff package](../../glossary.html#term-Handoff-Package) that includes all source code, all documentation,
and all distributed Attack Phase artifacts. The team must approve of the
handoff package before advancing into the Attack Phase. The Handoff Package
serves as the final opportunity for teams to verify that they have not left
any sensitive system materials in their repositories that they do not wish to
be publicly known. If the team decides not to approve the handoff package to
make a change to their design, they will have to go through the full Handoff
process again before moving to the Attack Phase. Minor modifications may be
exempted from the resubmission process at the discretion of the organizers.

Warning

Teams are not allowed to modify their designs after reviewing and
approving the [handoff package](../../glossary.html#term-Handoff-Package), so be sure to look through everything
before signing off

If a submitted design passes functional testing, that team will move into the
Attack Phase two days after the initial submission to allow time for organizers
to verify and process the submission. This two-day turnaround period may be
shortened at the discretion of the organizers. Therefore, the date and time of
transition from Design Phase to Attack Phase may vary between teams. For
example: If Team A and Team B both submit systems on the handoff date, but only
Team A’s system passes the tests, then only Team A will move into the Attack
Phase while Team B remains in the Design Phase until they submit a system that
meets all functional requirements.

The eCTF organizers will announce on the Attack Phase
[Zulip](../../about/zulip.html) channel the time of an incoming team as soon as a team
has confirmed their Handoff Package. This is intended to make it easier for
teams to predict when new designs are incoming and to avoid disadvantaging teams
not in the same time zone as the MITRE organizers. The length of notice will
vary due to a number of factors out of the organizers’ control.

## Rejected Designs[¶](#rejected-designs "Permalink to this heading")

If a system is not accepted, the eCTF organizers will inform the team and
provide an explanation for why the design did not pass testing. The submitting
team must then revise their design and submit a new version to the organizers.

