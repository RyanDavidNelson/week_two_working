# Submission Process

Source: https://rules.ectf.mitre.org/2026/handoff/submission_process.html

# Submission Process[¶](#submission-process "Permalink to this heading")

When a team has finished testing their design using the [Automated Testing Service](../system/api.html) they will want to submit their design to the Organizers
in order to enter the attack phase. To do this they begin a “submission” flow on the tesing service. The service will verify the functional correctness of the
design (using the same tests) and if it passes will package the design and then wait for both team and organizer approval. Once a design has been
successfully submitted by a team this flow cannot be used again by that team.

## Approval Process[¶](#approval-process "Permalink to this heading")

When submitting a design apart from the jobs that test functional correctness there will be two additional jobs: `team_approval` and `organizer_approval`.
These will be “pending” jobs which means they won’t start until input is provided. What this means for a team who would like to submit is that it is their responsability
to look through the generated attack package and make sure that they are satisfied with having that package sent out to other teams during the attack phase.
Once a team has made their decision they should make a json file filled with the following body:

```
{"approve": true}
```

In this case a team would be accepting that attack package, if `approve` was set to false then the team would be rejecting that attack package.
The `organizer_approval` job is the same except it is for the organizers to approve or reject a team’s design. This job is marked private
which means that team’s can’t interact with it. Just like the other approval job if it has completed it means the organizers have accepted the design,
if it has failed it means the organizers have rejected the design, and if it’s still pending it means the organizers have not finished reviewing the
package.

The submit flow only succeedes if both the team and organizers approve of the package. If it does then the encrypted attack package will
become immediately available for download, and the associated key to unecrypt will be posted to Zulip the moment this team enters the attack phase.

