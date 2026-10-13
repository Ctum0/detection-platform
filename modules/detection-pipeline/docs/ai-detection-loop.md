# AI detection loop

How a new detection gets proposed by a model, reviewed by a person and
shipped by the normal pipeline. DET-013 (T1547.001, PR #7) is the one rule
that has gone through it so far.

```text
trigger (manual, every 6 h, or console button)
  -> n8n "Detection Gap Analyst"
       fetch attack matrix + existing Sigma file list
       -> LLM drafts a Sigma rule (one retry on rejection)
       -> sigma-validator service pre-checks it
       -> branch + commit + pull request on detection-platform
       -> register the proposal in the operator console
       -> Telegram notification, callback to the console
  -> operator console: a human approves or rejects
       approve -> merge gate (PR open, CI green) -> merge to main
  -> validate.yml (CI) -> convert-deploy.yml -> deploy-wazuh.yml (CD)
  -> a human runs the attack (ART) and records the validation in the console
```

Nothing in this loop deploys a rule without a human approving the PR in the
console, and the merge is gated on CI. The model never touches the Wazuh
manager.

## Components

| Component | Where it lives | Documented here |
|---|---|---|
| Detection Gap Analyst | n8n workflow on the VPS | Yes, below |
| sigma-validator | Container on the n8n docker network | Yes, below (source not in this repo) |
| LLM gateway and model (hermes) | A container on the lab network | Not documented here; owner to describe |
| Operator console | Separate repo `Ctum0/operator-console` | Summary below; its own README is authoritative |
| detection-platform CI/CD | This repo, `.github/workflows/` | `platform/workflows-docs.md` |

## Detection Gap Analyst (n8n)

Workflow name `Detection Gap Analyst`, active, 38 nodes as exported on
2026-10-14. The export is not committed to this repo unless a file named
`modules/soar/gap-analyst-workflow-export.json` is present; if it is, it may
be a newer, edited version than the 38-node workflow described here, so
check its node list against this section.

**Triggers (three).** All three feed a `Run context` code node that records
where the run came from and the console `trigger_id`, if there is one.

| Trigger | Notes |
|---|---|
| Manual Trigger | Started from the n8n editor |
| Every 6 hours | Schedule trigger, 6-hour interval |
| Console trigger (webhook) | POST, path `propose-detection`, header authentication through an n8n credential. Fired by the console's "Request proposal" button; carries a `trigger_id` of the form `trg-<hex>` |

**Flow.**

1. `Fetch attack matrix` downloads `modules/detection-pipeline/docs/attack-matrix.md`
   from `main` on raw.githubusercontent.com. `Fetch existing Sigma list`
   lists `detections/sigma/` through the GitHub contents API (credentialed).
2. `Assemble context` parses the matrix table (Technique and Status columns),
   builds the list of covered techniques and existing rule files, and adds a
   fixed environment statement and a list of candidate techniques. The
   statement tells the model the Linux victim's auditd is broken (so no Linux
   rules), that there is no AD domain and no cloud sources.
3. `LLM draft` posts the prompt to the LLM gateway's chat completions
   endpoint (OpenAI-compatible, credentialed through an n8n Header Auth
   credential, 300 s timeout). The gateway address is on the lab network and
   is not recorded here.
4. `Validate fields` parses the model's reply as JSON (with some repair of
   common formatting problems), requires the fields `gap_analysis`,
   `technique`, `title`, `reasoning` and `sigma_yaml`, and checks the
   technique ID against an embedded snapshot of current Windows ATT&CK
   Enterprise techniques (version 19.2 in the code), rejecting revoked,
   non-Windows and unknown IDs. It also reports provider errors that the
   gateway returns as normal replies. A failure routes to the retry path.
5. `Sigma pre-check` posts the draft Sigma YAML to the sigma-validator service
   (`POST /check`, 120 s timeout, errors not fatal to the node). `Sigma verdict`
   accepts only HTTP 200 with `ok: true`; otherwise it collects the validator's
   error list.
6. Retry, once. `Build retry request` appends the rejected answer and the
   reason to the conversation and asks the model for a corrected JSON object.
   The retry repeats the same three steps (`LLM draft (retry)`,
   `Validate fields (retry)`, `Sigma pre-check (retry)`, with their `Valid?` and
   `Sigma OK?` checks). A second failure goes to `Failure result`.
7. `Accepted draft` marks the attempt number (1 or 2). Then, through the GitHub
   API with a credentialed header: `Get main SHA`, `Create branch`,
   `Commit rule file` (writes the Sigma file under `detections/sigma/`), and
   `Open PR` (title `AI proposal: <technique> <title>`, body with the gap
   analysis and reasoning, and a line stating human review is required).
8. `Build proposal` and `Register in console` post the proposal to the
   operator console `POST /api/proposals`. `Check registration` and
   `Route registration` branch on the response: 201 is success; 429 (the
   console's rate limit) fails the run without retry; 422 goes to
   `Repair payload`, which adjusts the fields named in the error text
   (for example `pr_number`, `technique`, length limits) and tries
   `Register in console (retry)` once; anything else fails.
9. `Success result` or `Failure result` builds one summary. `Telegram notify`
   sends it (the n8n Telegram credential; the chat ID is a literal in the node
   parameters). `From console trigger?` then, for console-started runs,
   `Report run result` calls `POST /api/triggers/<trigger_id>/result` so the
   console can show the run as succeeded or failed.

**Credentials.** The GitHub, LLM gateway, console and webhook calls use n8n
credential objects (Header Auth, Telegram). This differs from the
SOC Alert Triage workflow, whose secrets are inline in node parameters (see
`modules/soar/README.md`).

**Known gaps.**

- Ordinary failures after the PR is opened (for example the console
  refusing registration) leave the branch and PR in GitHub for a person to
  clean up.
- The workflow is the only place the prompt and the candidate-technique list
  are kept. Without a committed export, a change to the n8n workflow is not
  reviewed anywhere.

## sigma-validator

A small Python HTTP service the workflow calls before it opens a PR. Its
purpose is to reject a draft that the repo's own CI would reject, so a broken
PR is not created.

- Endpoint: `POST /check` on port 8080 inside its container. The request body
  is `{"sigma_yaml": "<rule text>"}`. A good draft returns HTTP 200 with
  `ok: true`; otherwise the response carries an `errors` list the workflow
  feeds back to the model.
- Checks: it mirrors what `validate.yml` runs, i.e. `sigma check` and a
  conversion with the Splunk backend, and adds structural checks and checks
  that the field names used are valid Sysmon fields.
- Network: reachable only from the n8n docker network (the workflow addresses
  it by container name). No port is published on the host.
- Source and image: not in this repo. Owner to add the source (or a link to
  its repo) and the image tag. It is a mirror of the CI checks, so a change to
  `validate.yml` (pySigma version, backend, flags) should be applied to it as
  well, otherwise the two will disagree.

## LLM gateway and the hermes container

The draft step and the SOC Alert Triage workflow both call an
OpenAI-compatible gateway (litellm) using the model name `Hermes Agent`. The
hermes container behind it is not described in this repo: image, host,
configuration, model backing and how it is kept running are all not
documented here; owner to describe. Do not treat the lab network address in the
n8n nodes as stable.

## Operator console

Repo: `Ctum0/operator-console` (FastAPI, single-file frontend, JSON files in a
`/data` volume, bearer-token auth). In the working copy it sits at
`operator-console/` inside this repository's directory, but it is a separate
git repository: it is not a git submodule (no `.gitmodules`), it has its own
history, and it is excluded locally through `.git/info/exclude`, so a clone of
this repo does not contain it. Its changes are separate commits and pull
requests in its own repo.

What it does, from its README:

- Holds proposals registered by the workflow with a status of `pending`,
  `merging`, `merged`, `merge_failed`, `rejected` or `validated`.
- Approve: runs a merge gate (PR open, at least one successful check, none
  failing or running), then merges the PR through the GitHub API with a
  fine-grained PAT. The merge triggers this repo's CI, then `convert-deploy.yml`.
- Reject and reopen with a reason; notes on a proposal; an audit log.
- Record validation: for a merged proposal, the operator records the Wazuh rule
  ID, the attack run and when it fired. This is the human step that closes the
  loop. DET-013 has not had it yet.
- Read-only panels for pipeline health (CI, self-hosted runner, Wazuh, n8n),
  ATT&CK coverage (parsed from `attack-matrix.md`) and activity.
- Trigger tracking: "Request proposal" calls the n8n `propose-detection`
  webhook; the workflow reports back through `POST /api/triggers/{id}/result`
  or by including the `trigger_id` when it registers.

Read the console's own `README.md` and `CLAUDE.md` for the API contract,
environment variables, backup and token rotation. They change faster than this
page.

## What a reader still cannot reproduce from this repo

- The sigma-validator source and image.
- The hermes container and LLM gateway configuration.
- A reviewed copy of the Detection Gap Analyst workflow (see above).
- The n8n credentials, which are intentionally not stored.
