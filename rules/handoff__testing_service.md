# Automated Testing Service

Source: https://rules.ectf.mitre.org/2026/handoff/testing_service.html

# Automated Testing Service[¶](#automated-testing-service "Permalink to this heading")

eCTF teams must use the Automated Testing Service to verify that
their design meets the [Functional Requirements](../specs/functional_reqs.html).

This year the testing service will interacted with through a web API.
The organizers have provided a python package which includes a client
for interacting with the testing server. This includes a CLI client included
with the eCTF public pip package.
as well as direct python functions one can import and use in their own
python scripts

Tip

The terms **Flows** and **Jobs** are both used in this section and for clarity they will be explained.

* **Flows:** These are a collection of testing jobs which represent running a full operation on the testing infrastructure. This could include testing a design, submitting a design, or running a remote scenario.
* **Jobs:** These are the components of a flow which need to be run. They may be reused between flows (e.g. pull-repo will commonly be reused). Within a flow jobs are ordered by dependencies and will only run if the jobs that they are dependent on succeed.

All teams will receive a private authorization token to identify themselves to the server.
If a team believes they have not received such a token they should reach out to the organizers.

## Set Up[¶](#set-up "Permalink to this heading")

First, make sure to invite the eCTF Organizers to your private repository:

* GitHub: <https://github.com/ectfmitre>
* GitLab: <https://gitlab.com/ectfmitre>

Warning

If you do not add the eCTF organizer to your repository, the API will be unable
to clone your design!

After installing the ectf public tool make sure to run the config command using

```
ectf config
```

This will let a user set the variables that will not change over the course of the competition, these include:

* **Token**, The private authorization token used to identify which team is submitting
* **Git URL**, The url used to pull the git repo for the team’s design e.g. <ssh://git@github.com/example.git>
* **API URL**, The url to hit the testing api, for this competition this will be <https://api.ectf.mitre.org>

Warning

When adding your git url it’s important you use the one that clones via ssh,
i.e. the link should look something like `ssh://git@github.com/example.git`
and NOT `https://git@github.com/example.git`. If you use `https` the API might not be able to clone your design!

---

There are four flows used for the competition which are:

* **clone**: Only clones the submitting team’s repo, used to test that the design’s repo is shared with the organizers, also awards a design phase flag.
* **test**: Runs the full suite of tests used to ensure a design is functionally correct.
* **submit**: Runs the full suite of tests and on a successful completion readies the package to submitted for the attack phase
* **remote**: Initiates a run of the [remote scenario](../flags/remote_scenario.html)

For the sake of this guide, only `test` will be used. To run any of these commands on another flow simply replace `test` with the desired flow

## Adding a flow to the queue[¶](#adding-a-flow-to-the-queue "Permalink to this heading")

To add a flow to the queue use:

```
#                  { git commit hash }
ectf api test submit deadbeef
```

On a success the CLI will respond with:

```
Successfully submitted test with ID: "4dac2e73-b2c1-4ce0-83fb-ab1653687ca4"
```

Where the ID is the given is the ID of that particular flow.

## List All Flows[¶](#list-all-flows "Permalink to this heading")

To list all the flows the team has queued use:

```
#                 { amount to list }
ectf api test ls -n X
```

This will return a list of the last X flows the team has queued. If -n is not given the default is 5.
The output will looks something like the following:

```
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┓
┃ Test ID                              ┃ When Submitted ┃ Status    ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━━━━━┩
│ e809f5df-861d-4127-9c34-ae51f87e8fe4 │ a month ago    │ Failed    │
│ ce1ba867-edf9-4ba9-a68c-01822f692fba │ a month ago    │ Failed    │
│ f5a001c9-c030-4a9e-9de9-e8e8c432eda5 │ a month ago    │ Succeeded │
│ 3c46449d-079b-4a4d-be2d-4fab840abedd │ 1 hour  ago    │ Succeeded │
│ 4dac2e73-b2c1-4ce0-83fb-ab1653687ca4 │ 2 minutes ago  │ Queued    │
└──────────────────────────────────────┴────────────────┴───────────┘
```

## Get Detailed Info From One Flow[¶](#get-detailed-info-from-one-flow "Permalink to this heading")

To list out all the jobs from a specific flow as well as their statuses run the following command

```
#                       { The flow ID }
ectf api test info 4dac2e73-b2c1-4ce0-83fb-ab1653687ca4
```

This will return a list of all the jobs associated with this flow and their results in the form:

```
Flow 2026-ectf-insecure-example
├── ID: 3c46449d-079b-4a4d-be2d-4fab840abedd
├── Submitted: 2026-1-15 20:05:16+00:00
├── Status: Succeeded
├── Parameters
│   ├── git_url:
│   │   ssh://git@github.com/example.git
│   └── commit_hash: deadbeef
└── Jobs
    ├── jobA
    │   ├── ID: 1185e353-d91c-468f-b406-ef61f42e7bb1
    │   ├── Has Output: True
    │   ├── Private: False
    │   └── Status: Succeeded
    ├── jobB
    │   ├── ID: 9a265187-1240-4725-8cd2-02ab7bd743d6
    │   ├── Has Output: False
    │   ├── Private: False
    │   └── Status: Succeeded
    └── jobC
        ├── ID: 484dffb5-6d19-4603-a890-b7f4dfcbfff9
        ├── Has Output: True
        ├── Private: False
        └── Status: Succeeded
```

Tip

The `Has Output` field indicates if the job produced any output that can be downloaded by the team, if the value is false it means the testing server
wil throw an error if a team tries to retrieve that job’s output

The `Private` field indicates if the job can be interacted with by the submitting team. A job who’s private value is marked true means that the job can
only be interacted with by the organizers.

## Get Output From a Job[¶](#get-output-from-a-job "Permalink to this heading")

To get the output produced by a job use:

```
#                           { Job ID }               { filename of zip }
ectf api test get 484dffb5-6d19-4603-a890-b7f4dfcbfff9 output.zip
```

This will return any output from the job with the associated id. The output will be a zipped file which will be stored
at the location specified in the command. This file can then be extracted and all the output files will be viewable.

## Cancel a Flow[¶](#cancel-a-flow "Permalink to this heading")

To cancel a flow that has not completed use:

```
#                           { Flow ID }
ectf api test cancel 4dac2e73-b2c1-4ce0-83fb-ab1653687ca4
```

## Update a Pending Job[¶](#update-a-pending-job "Permalink to this heading")

Some flows, `submit` and `remote`. Have jobs that will enter a “Pending” state.
This means that the job isn’t queued yet and is waiting for some additional input to be provided
by the submitting team. The details of what specific input is needed for these pending jobs is specific
for each flow and is expanded upon in [Submission Process](submission_process.html) and [Remote Scenario](../flags/remote_scenario.html).

To provide input to a pending job use:

```
#                           { Job ID }                    { input json file }
ectf api submit update 484dffb5-6d19-4603-a890-b7f4dfcbfff9 args.json
```

Where `args.json` is a json file filled with the input needed for that pending job.

## Submitting a Team Photo[¶](#submitting-a-team-photo "Permalink to this heading")

This year we will be using our testing server to handle teams submitting their team photos.

The command to submit a team photo is:

```
#            { Path to the PNG }
ectf api photo team_photo.png
```

The photo must be in the form of a PNG and when submitted will reward the team with the associated design phase flag:

```
Congrats! Your photo was accepted! Please submit the following flag: ectf{example_deadbeef}
```

## Submitting a Design Doc[¶](#submitting-a-design-doc "Permalink to this heading")

This year we will be using our testing server to handle teams submitting their design docs.

The command to submit a design doc is:

```
#            { Path to the PDF }
ectf api photo design.pdf
```

The design doc must be in the form of a PDF and when submitted will reward the team with the associated design phase flag:

```
Congrats! Your design doc was accepted! Please submit the following flag: ectf{example_deadbeef}
```

## Submit a Digest for Steal Design Flag[¶](#submit-a-digest-for-steal-design-flag "Permalink to this heading")

This command is only accessible to teams in the attack phase.
After obtaining a digest for [Steal Design](../flags/attack_flags.html#steal-design-flag) a team can submit it to the testing service using

```
#            { Target Team } { digest }
ectf api steal mitre           ec11607bcc1e01b698a923c01e01b6c716e36142f646e00938ee8b358865ed21039ee28fe0ff71330ed70f6a5be788dd7df6263e9b4d385903a857ea30032ad5
```

With a correct digest a team will be awarded the associated attack phase flag:

```
Congrats! The hash was correct! Please submit the following flag: ectf{example_deadbeef}
```

## List and Download Attack Packages[¶](#list-and-download-attack-packages "Permalink to this heading")

These commands are only accessible to teams in the attack phase.
To see all the attack packages available for download use

```
ectf api package list
```

This will give you the list of teams who have attack packages ready to download:

```
The following packages are available:
    mitre
    team1
    team2
```

To then download an attack package run:

```
#                  { package name }
ectf api package get mitre
```

Which by default will download the attack package to `{package_name}.enc`.

This year attack packages become immediately available for download as soon attack packages are approved and
before the team officially enters the attack phase. However, these attack packages are encrypted and
the decryption key will only be posted to Zulip the moement the team officially enters the attack phase. This
gives teams the oppurtunity to download attack packages in advance.

To decrypt a an attack package use the following command:

```
openssl enc -d -aes-256-cbc -pbkdf2 -salt -k 010203040506070809000a0b0c0d0e0f -in mitre.enc -out mitre.zip
```

Where instead of `-k 010203040506070809000a0b0c0d0e0f` the decryption key
sent on Zulip would be used. To decrypt the Attack The Reference attack package
(which can be found on [Design Phase Flags](../flags/design_flags.html)) use
the key given in this example.

---

As a last note when using the CLI a team can always add the `--help` flag to get info on the various commands, what they do, and what input they require.
Some teams might find this easier to use as a reference then using this page.

---

This tool is provided to interface with the testing server, many teams might find this easier to use them individually
using the python commands and copy pasting flow and job ids.
For teams interested interested in building their own tools to interface with
the testing service or who want to interact with the testing api directly please see please see [eCTF API](../system/api.html).

