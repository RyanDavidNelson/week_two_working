# eCTF API

Source: https://rules.ectf.mitre.org/2026/system/api.html

# eCTF API[¶](#ectf-api "Permalink to this heading")

The eCTF team creates a web API to allow teams to interact with automated tooling and
verify that their design meets the [Functional Requirements](../specs/functional_reqs.html).

This year the interface for the testing service will be through a web API.
As part of the eCTF public tools the organizers have provided a python utility
which includes a client for interacting with the testing server.
This page is for those who want more details on how exactly the testing server
works so they can, for example:

* Have more familiarity with terms the organizers might use when discussing the testing infrastructure
* Directly make http requests to the testing api (we will use `curl` as an example) and understand the server’s responses
* Create their own automation for interacting with the testing server

This page assumes some basic familiarity with http and using a web API for information on these subjects please see [here](https://www.geeksforgeeks.org/how-to-use-an-api-the-complete-guide/).

Tip

The terms **Flows** and **Jobs** are both used in this section and for clarity they will be explained.

* **Flows:** These are a collection of testing jobs which represent running a full operation on the testing infrastructure. This could include testing a design, submitting a design, or running the remote scenario.
* **Jobs:** These are the components of a flow which need to be run. They may be reused between flows (e.g. pull-repo will commonly be reused). Within a flow jobs are dependent on other jobs, and a job will only run if the jobs that it is dependent on succeed.

All teams will receive a private authorization token to identify themselves to the server.
This token will be used in every request made to the server.
If a team believes they have not received such a token they should reach out to the organizers.

## General Endpoint Strucutre[¶](#general-endpoint-strucutre "Permalink to this heading")

All endpoints on the server will begin with `/api`.
The endpoints on the server are devided into 3 main groups.
These groups serve to logically devide up the functionality of endpoints

* **flag**: This group of endpoints all involve a team submitting something to the organizers and potentially recieving a flag in return. These endpoints all have the form `/api/flag/...`

Flag Endpoints[¶](#id9 "Permalink to this table")

| Details | Endpoint | Method | Functionality |
| --- | --- | --- | --- |
| [Submit Team Photo](#submit-photo) | `/api/flag/team_photo/` | POST | Submit a team photo to the organizers |
| [Submit Design Doc](#submit-doc) | `/api/flag/design_doc/` | POST | Submit a design doc to the organizers |
| [Steal Design Flag](#steal-design) | `/api/flag/steal_design/{target_team_name}` | POST | Submit a hash for the steal design scenario |

* **package**: This group of endpoints are all related to getting attack packages. These endpoints all have the form `/api/package/...`

Package Endpoints[¶](#id10 "Permalink to this table")

| Details | Endpoint | Method | Functionality |
| --- | --- | --- | --- |
| [Package Names](#package-names) | `/api/package/` | GET | Get names of all teams with attack packages |
| [Get Package](#get-package) | `/api/package/{team_name}/` | GET | Get the encrypted attack package for given team |

* **flow**: This group of endpoints has all the functionality relating to submitting, viewing the status, and viewing the output of flows. These endpoints all have the form `/api/flow/{flow_name}/...`

Flow Endpoints[¶](#id11 "Permalink to this table")

| Details | Endpoint | Method | Functionality |
| --- | --- | --- | --- |
| [List All Flows](#list-flow) | `/api/flow/{flow_name}/` | GET | Check currently queued flows |
| [Queue Flow](#queue-flow) | `/api/flow/{flow_name}/` | POST | Add a flow to queue |
| [Flow Details](#flow-details) | `/api/flow/{flow_name}/{flow_id}/` | GET | Get the results of all jobs for a flow |
| [Cancel Flow](#cancel-flow) | `/api/flow/{flow_name}/{flow_id}/cancel/` | POST | Cancel the selected running flow |
| [Job Result](#job-result) | `/api/flow/{flow_name}/job/{job_id}/` | GET | Get the output of a specific job |
| [Pending Job](#pending-job) | `/api/flow/{flow_name}/{job_id}/` | PATCH | Give input to a job in the “Pending” state |

---

## Submit Team Photo[¶](#submit-team-photo "Permalink to this heading")

This endpoint is used to submit your team’s photo to the Organizers and recieve the corresponding flag. The submitted image must be of png format.

**Inputs:**

| Header | Body |
| --- | --- |
| `Authorization: Bearer {team_token}` | `team_photo: **contents_of_file` |
| The private team token given by Organizers | A png file should be supplied with the post request |

**Return Body on Success:**

```
{ "flag_hex" : "str_flag_hex" }
```

**Endpoint’s Return Codes:**

| Status Code | Meaning |
| --- | --- |
| `200` | Success, organizers have recieved team’s photo |
| `401` | The authorization token given is invalid |
| `413` | The submitted file is too large to process |
| `422` | Validation error, either http body is misformed or file is not of type png |
| `500` | Internal error, likely from an aws outage |

**Example curl request:**

```
curl --request POST 'https://api.ectf.mitre.org/api/flag/team_photo/' --header 'Authorization: Bearer example-token' -F "team_photo=@/path/to/your/image"
```

---

## Submit Design Doc[¶](#submit-design-doc "Permalink to this heading")

This endpoint is used to submit your team’s design document to the Organizers and recieve the corresponding flag. The submitted file must be of pdf format.

**Inputs:**

| Header | Body |
| --- | --- |
| `Authorization: Bearer {team_token}` | `design_doc: **contents_of_file` |
| The private team token given by Organizers | A pdf file should be supplied with the post request |

**Return Body on Success:**

```
{ "flag_hex" : "str_flag_hex" }
```

**Endpoint’s Return Codes:**

| Status Code | Meaning |
| --- | --- |
| `200` | Success, organizers have recieved team’s design document |
| `401` | The authorization token given is invalid |
| `413` | The submitted file is too large to process |
| `422` | Validation error, either http body is misformed or file is not of type pdf |
| `500` | Internal error, likely from an aws outage |

**Example curl request:**

```
curl --request POST 'https://api.ectf.mitre.org/api/flag/design_doc/' --header 'Authorization: Bearer example-token' -F "design_doc=@/path/to/your/image"
```

---

## Steal Design Flag[¶](#steal-design-flag "Permalink to this heading")

Submit the hash printed from an HSM by the bootloader for the steal\_design flag, only accessible to teams in the attack phase.
Will only return a maximum of one flag per request.

**Inputs:**

| Header | Path | Json Body |
| --- | --- | --- |
| `Authorization: Bearer {team_token}` | `../steal_design/{target_team_name}` | `"hash_to_submit"` |
| The private team token given by Organizers | The team who’s flag you wish to take should be supplied in the url path | A simple string containging the hash you’d like to submit |

**Return Body on Success:**

```
{ "flag_hex" : "str_flag_hex" }
```

**Endpoint’s Return Codes:**

| Status Code | Meaning |
| --- | --- |
| `200` | Success, a correct digest has been submitted |
| `400` | Given digest is incorrect OR team being targetted is not in the attack phase |
| `401` | The authorization token given is invalid |
| `403` | This team is not in the attack phase |
| `404` | Team being targetted does not exist |
| `422` | Validation error, http body is misformed |

**Example curl request:**

```
curl --request POST 'https://api.ectf.mitre.org/api/flag/steal_design/mitre/' --header 'Authorization: Bearer example-token' --json "example_digest"
```

---

## Package Names[¶](#package-names "Permalink to this heading")

Get the list of all teams who have attack packages stored on the server. Only accessible to teams in the attack phase.

**Inputs:**

> None

**Return Body on Success:**

```
[ "mitre", "mitre2", "mitre3" ]
```

**Endpoint’s Return Codes:**

| Status Code | Meaning |
| --- | --- |
| `200` | Success, a correct hash has been submitted |
| `401` | The authorization token given is invalid |
| `403` | This team is not in the attack phase |

**Example curl request:**

```
curl --request GET 'https://api.ectf.mitre.org/api/package' --header 'Authorization: Bearer example-token'
```

---

## Get Package[¶](#get-package "Permalink to this heading")

Retrieve the encrypted zip for an attack package. Only accessible to teams in the attack phase.

**Inputs:**

| Header | Path |
| --- | --- |
| `Authorization: Bearer {team_token}` | `../package/{team_name}` |
| The private team token given by Organizers | The team name of the attack package you would like should be provided in the url path |

**Return Body on Success:**

`**file content of encrypted attack package**`

**Endpoint’s Return Codes:**

| Status Code | Meaning |
| --- | --- |
| `200` | Success, a correct hash has been submitted |
| `401` | The authorization token given is invalid |
| `403` | This team is not in the attack phase |
| `404` | Package name does not exist. |

**Example curl request:**

```
                                                                                     #/{package_name}
curl --request GET 'https://api.ectf.mitre.org/api/package/mitre' --header 'Authorization: Bearer example-token'
```

---

## List All Flows[¶](#list-all-flows "Permalink to this heading")

To list all the flows of a specifc type the team has queued use:

**Inputs:**

| Header | Body |
| --- | --- |
| `Authorization: Bearer {team_token}` | `../flow/{flow_name}/?num={num}` |
| The private team token given by Organizers | An optional query parameter (default 0 when not included) can be provided to select how many flows you’d like to see, 0 returns all flows. |

**Return Body on Success:**

`List[`[Flow:Schema](#flow-schema) `]`

**Endpoint’s Return Codes:**

| Status Code | Meaning |
| --- | --- |
| `200` | Success, a correct hash has been submitted |
| `401` | The authorization token given is invalid |
| `422` | Validation Error, num given is less than 0 |

**Example curl request:**

```
curl --request GET 'https://api.ectf.mitre.org/api/flow/test/?num=0' --header 'Authorization: Bearer example-token'
```

---

## Queue Flow[¶](#queue-flow "Permalink to this heading")

Queue a testing flow of the specified type to the testing server.

**Inputs:**

| Header | Json Body |
| --- | --- |
| `Authorization: Bearer {team_token}` | `{"git_url" : "example.git", "commit_hash" : "deadbeef" }` |
| The private team token given by Organizers | The parameters being used for the queued flow, has to be of the form above to specify the git repo and branch to use |

**Return Body on Success:**

UUID of the newly queued flow e.g:

```
"3fa85f64-5717-4562-b3fc-2c963f66afa6"
```

**Endpoint’s Return Codes:**

| Status Code | Meaning |
| --- | --- |
| `201` | Success/Created, a flow has successfully been queued |
| `401` | The authorization token given is invalid |
| `409` | Conflict, This team already has a flow of this type queued |
| `422` | Validation Error, json body input is misformed |

**Example curl request:**

```
curl --request POST 'https://api.ectf.mitre.org/api/test' --header 'Authorization: Bearer example-token' -d '{"git_url" : "example.git", "commit_hash" : "deadbeef"}'
```

---

## Flow Details[¶](#flow-details "Permalink to this heading")

Gives all the details from a specific flow, includes info on all the jobs contained within this flow

**Inputs:**

| Header | Path |
| --- | --- |
| `Authorization: Bearer {team_token}` | `../flow/{flow_name}/{flow_id}/` |
| The private team token given by Organizers | The desired flow’s flow uuid should be provided in the url path |

**Return Body on Success:**

This returns a [Flow:Schema](#flow-schema)

**Endpoint’s Return Codes:**

| Status Code | Meaning |
| --- | --- |
| `200` | Success, the flow’s details have been provided |
| `401` | The authorization token given is invalid |
| `404` | Not Found, The provided flow id does not lead to a valid flow |
| `422` | Validation Error, the provided flow id was not in the form of a UUID |

```
                                                                                     # /{flow_id}
curl --request GET 'https://api.ectf.mitre.org/api/flow/test/3fa85f64-5717-4562-b3fc-2c963f66afa6/' --header 'Authorization: Bearer example-token'
```

---

## Cancel Flow[¶](#cancel-flow "Permalink to this heading")

Cancels the currently queued flow for the specified flow type

**Inputs:**

| Header | Path |
| --- | --- |
| `Authorization: Bearer {team_token}` | `../flow/{flow_name}/{flow_id}/cancel` |
| The private team token given by Organizers | The cancelled flow’s flow uuid should be provided in the url path |

**Return Body on Success:**

None

**Endpoint’s Return Codes:**

| Status Code | Meaning |
| --- | --- |
| `204` | Success, No content |
| `400` | This flow already completed and can’t be cancelled |
| `401` | The authorization token given is invalid |
| `404` | Not Found, The provided flow id does not lead to a valid flow |
| `422` | Validation Error, the provided flow id was not in the form of a UUID |

```
                                                                                     # /{flow_id}
curl --request POST 'https://api.ectf.mitre.org/api/flow/test/3fa85f64-5717-4562-b3fc-2c963f66afa6/cancel/' --header 'Authorization: Bearer example-token'
```

---

## Job Result[¶](#job-result "Permalink to this heading")

Gives a zip file containing all the outputs of a job.

**Inputs:**

| Header | Path |
| --- | --- |
| `Authorization: Bearer {team_token}` | `../flow/{flow_name}/{job_id}/` |
| The private team token given by Organizers | The job’s job uuid should be provided in the url path |

**Return Body on Success:**

`**file content of job output zip**`

**Endpoint’s Return Codes:**

| Status Code | Meaning |
| --- | --- |
| `200` | Success, output has been provided |
| `400` | This job has no output to pull |
| `401` | The authorization token given is invalid |
| `404` | Not Found, The provided job id does not lead to a valid job |
| `422` | Validation Error, the provided job id was not in the form of a UUID |

```
                                                                                         # /{job_id}
curl --request GET 'https://api.ectf.mitre.org/api/flow/test/job/981b2de7-f03f-4780-9cd1-1b6a893a0221/' -o output.zip --header 'Authorization: Bearer example-token'
```

---

## Pending Job[¶](#pending-job "Permalink to this heading")

Provide input to a job currently in the “pending” state. This is for adding user input to a job,
where the input the user submits might depend on the result and output of previous jobs.
This is mainly used for the Submission process and the [Remote Scenario](../flags/remote_scenario.html).

**Inputs:**

| Header | Path | Json Body |
| --- | --- | --- |
| `Authorization: Bearer {team_token}` | `../flow/{flow_name}/{job_id}/` | `{"prop_1" : "value_1", "prop_2" : "value_2"}` |
| The private team token given by Organizers | The job’s job uuid should be provided in the url path | An arbitrary dict of key value pairs used as input for the job |

**Return Body on Success:**

`**file content of job output zip**`

**Endpoint’s Return Codes:**

| Status Code | Meaning |
| --- | --- |
| `204` | Success, No content |
| `401` | The authorization token given is invalid |
| `404` | Not Found, The provided job id does not lead to a valid job |
| `422` | Validation Error, the provided job id was not in the form of a UUID |

```
       # Note the PATCH method                                                 # /{job_id}
curl --request PATCH 'https://api.ectf.mitre.org/api/flow/test/job/a432199e-fb5b-589a-8bcf-cc3a8f3e0722/' --header 'Authorization: Bearer example-token' -d '{"prop_1" : "value_1", "prop_2" : "value_2"}'
```

---

As a final note the program used to build the web app also creates autogenerated documentation which can be found at <https://api.ectf.mitre.org/docs/>.
That being said the organizers consider the rules pages to be the official source of documentation on the web API and make no guarantee about the quality or accuracy of the autogenerated documentation.

## `Flow:Schema`[¶](#flow-schema "Permalink to this heading")

* `id: uuid`
* `submit_time: datetime`
* `name: string`
* `completed: boolean`
* `params: dict[str:str]`
* `jobs: list[Schema:Job]`

```
{
    "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "submit_time": "2026-01-29T14:53:48.335Z",
    "name": "test",
    "completed": false,
    "params": {
        "git_url": "example.git",
        "commit_hash": "deadbeef"
    }
    "jobs": [
        {
            "id": "981b2de7-f03f-4780-9cd1-1b6a893a0221",
            "name": "jobA",
            "status": "succeeded",
            "has_artifacts": true,
            "private": false,
        },
        {
            "id": "2d7c01fd-76b6-4221-9c13-0342a2ed902d",
            "name": "jobB",
            "status": "failed",
            "has_artifacts": false,
            "private": false,
        },
        {
            "id": "7e782e6c-2e35-4a3e-9702-1f46fed7cd2b",
            "name": "jobC",
            "status": "queued",
            "has_artifacts": false,
            "private": false,
        }
    ]
}
```

