# CI/CD workflows

How the three GitHub Actions workflows in `.github/workflows/` turn a Sigma
rule into a live Wazuh alert, and why they're built the way they are.

## Overview

Three workflows, two different trust boundaries:

- **CI — `validate.yml`** (`Validate Sigma rules`): GitHub-hosted runner,
  no access to the lab. Its only job is to keep `detections/sigma/`
  honest — syntax-check every rule and keep the auto-generated Splunk
  SPL in sync with it.
- **Convert — `convert-deploy.yml`** (`Convert Sigma to Wazuh and
  deploy`): GitHub-hosted runner. After CI passes on `main`, turns new
  Sigma rules into Wazuh rules, merges them into
  `detections/wazuh/custom_rules.xml` and starts the CD workflow.
- **CD — `deploy-wazuh.yml`** (`Deploy rules to Wazuh`): self-hosted
  runner living on the same VPS as the Wazuh manager. Its job is to get
  `detections/wazuh/custom_rules.xml` onto that manager and confirm it's
  actually live, not just uploaded.

CI and CD trigger on push-to-`main` for the paths they care about; CI also
runs on pull requests (read-only there — see below). Convert runs after CI
succeeds on `main` and starts CD itself (see below).

## CI — Validate Sigma rules

Trigger: any push or PR touching `detections/sigma/**`, or a push to the
workflow file itself.

1. **Checkout** with `persist-credentials: true` — needed later so the
   autocommit step can push back as `GITHUB_TOKEN`.
2. **Install `sigma-cli`** plus the Splunk pySigma backend.
3. **`sigma check detections/sigma/`** — schema, syntax, and ATT&CK-tag
   validation. Zero errors required before anything downstream is
   trusted.
4. **Convert to Splunk SPL** — `sigma convert -t splunk --without-pipeline`
   over the whole directory. One rule file is excluded first:
   `ssh_success_after_failures.yml` uses a `temporal_ordered` correlation
   that the Splunk backend doesn't support, so it's moved to `/tmp` for
   the conversion and moved back after. Worth knowing: the
   `{stem}.spl` output template has no `{index}`, so for a multi-doc file
   (e.g. `ssh_bruteforce.yml`, which has a base rule *and* a correlation)
   only the last document's query survives in the `.spl` file — for that
   file, that's correctly the event-count correlation, the actually
   deployable detection.
5. **Commit generated SPL** — `git add -A detections/splunk/`, commit
   with `[skip ci]`, push. Guarded by `if: github.event_name !=
   'pull_request'`: a fork's PR can't push back credentials it doesn't
   have, and `[skip ci]` guarantees this autocommit never re-triggers
   itself into a loop.

## Convert — Sigma to Wazuh

Trigger: `workflow_run` on **Validate Sigma rules** completing successfully
for a push to `main` (pull-request runs are ignored), or manual dispatch.
Running after CI instead of alongside it means the Sigma has already passed
`sigma check` and CI's own SPL autocommit has landed, so the two never race
to push.

1. **Convert** — `platform/converters/sigma_to_wazuh.py --anchor if_group`
   regenerates every Sigma rule into `/tmp/fresh_rules.xml`. Rules it
   cannot express faithfully (`or`, multi-field negated filters, unmapped
   fields) are skipped with a reason, never emitted with different logic.
2. **Merge** — `platform/converters/merge_wazuh_rules.py` merges that into
   the live `custom_rules.xml`. Rules are matched by Sigma identity
   (`<file> :: <title>`), recorded with their deployed ID in
   `platform/converters/wazuh_rule_ids.json`, not by the converter's
   positional IDs (those shift whenever a Sigma file is added). Hand-tuned
   live rules win; live-only tuning rules (100013, 100020) are kept; new
   rules get the next free ID. With nothing new the file is left
   byte-identical, so "No Wazuh changes" is a reliable signal.
3. **Validate** — the merged file must parse and every rule ID must be
   unique.
4. **Commit and dispatch** — new rules are committed to `main` (with a
   rebase and retry), then `deploy-wazuh.yml` is started with
   `gh workflow run`. A push made with `GITHUB_TOKEN` never triggers
   other workflows, so relying on CD's push trigger would silently skip
   the deploy; `workflow_dispatch` is the documented exception.

Known limitations: renaming a Sigma file or its `title` gives it a new
identity, so it would be added again under a new ID next to the old live
rule (update `wazuh_rule_ids.json` in the same commit when renaming).
Temporal correlations (DET-010) have no Wazuh equivalent and stay manual.

## CD — Deploy rules to Wazuh

Trigger: push to `main` touching `detections/wazuh/**`.

Runs on `self-hosted` rather than a GitHub-hosted runner because the
Wazuh manager's API is only reachable at `https://localhost:55000` from
the VPS itself — the runner lives on that same box (see "Runner
architecture" below), so there's no need to expose the API publicly or
manage a VPN just for CI.

1. **Deploy via API** — authenticate against `/security/user/authenticate`
   with a password read from a file on the runner host
   (`WAZUH_API_PASS_FILE`, never a repo secret), then `PUT
   /rules/files/local_rules.xml?overwrite=true` with
   `detections/wazuh/custom_rules.xml` as the body. The step explicitly
   captures the HTTP status code and greps the response body for
   `"error": 0` before calling it a success — see "the hot-reload lesson"
   below for why a bare `curl -sk` isn't good enough here.
2. **Restart the manager** — `docker restart single-node-wazuh.manager-1`,
   then confirm agents reconnect (`agent_control -l | grep -c Active`).
   This step exists because of a real bug, not caution for its own sake:
   see below.
3. **Verify rules loaded** — a fresh `GET /rules/files/local_rules.xml`
   confirms rule `100001` is present in what the manager now reports as
   loaded, not just what was uploaded.

### The hot-reload lesson

The API's `PUT` returns HTTP 200 and `"error": 0` the moment the file is
written to disk — that is not the same thing as the rule being live.
In this single-node docker deployment, `analysisd` does not hot-reload
rule files from a `PUT` alone; a manager restart is required before an
edited or newly added rule actually starts evaluating events. This
produced a genuinely confusing debugging session during the Adversary
Emulation module's Workstream 1 close-out: a parent-ID fix to rule 100007 (see
`../modules/detection-pipeline/docs/detections/det-011-security-log-cleared.md`)
looked fully deployed — clean 200, `error: 0` — but the rule still
wouldn't fire on re-test, because the manager was still running the old
in-memory rule set. The restart step above was added specifically to
close that gap; it's the reason step 2 exists at all. Distilled version
in `../shared/lessons-learned.md` (Pipeline/CD).

The original deploy step also used to run bare `curl -sk`, which swallows
HTTP errors and exits 0 — the workflow could show fully green while the
manager silently kept running stale rules. Fixed by capturing the status
code and response body explicitly and failing loudly on anything but
200 + `error: 0`. Same principle as the hot-reload issue: a CI/CD step
should prove the thing it claims happened, not just that its own command
didn't crash.

## Runner architecture

The self-hosted runner for `deploy-wazuh.yml` is co-located on the VPS
running the Wazuh manager (docker single-node — manager, indexer,
dashboard; see `../shared/architecture.md`). That's a deliberate choice,
not an accident of setup: the deploy step talks to `localhost:55000`
directly, so there's no public-facing Wazuh API port to secure or VPN
tunnel to maintain just for CI. The API credentials live in a file on
that host (a path set by `WAZUH_API_PASS_FILE`), outside the
repo and outside GitHub Secrets — the runner already has local
filesystem access, so there's no reason to duplicate the credential into
another store.

## Deploy safety constraints

`detections/wazuh/custom_rules.xml` must stay free of XML comments — the
Wazuh 4.14 API's rule-upload parser crashes (500 / PicklingError) on
comment blocks containing HTML-escaped entities like `&gt;` or `&amp;`.
Because of that, the rule-ID-to-Sigma-file mapping that would normally
live in a header comment instead lives in
`../detections/wazuh/DEPLOY-NOTES.md`, and the *generator's* output
(before hand-tuning) puts that mapping in a comment only when producing
a throwaway/reviewed file, never the deployed one directly. See
`converters/README.md` for the converter's hand-review deltas that
`custom_rules.xml` carries beyond what the generator produces on its own.

## Debugging war stories

Beyond the hot-reload lesson above, four other issues surfaced while
building this pipeline (full narrative in
`../modules/detection-pipeline/docs/pipeline-demo/README.md`):

1. **Silent `curl -sk` failures** — covered above.
2. **Duplicate rule IDs** — a `local_rules.xml.bak-*` file left inside
   the manager's rules directory was loaded by `analysisd` alongside the
   live file, double-defining every custom rule; "only first occurrence
   considered" made which version won a coin flip. Fixed by keeping
   backups out of the rules directory.
3. **Telemetry-stall red herring** — Sysmon events appeared to stop
   flowing during testing; root cause was benign (idle victim VMs at
   ~4:45 AM genuinely have nothing to send), but combined with the
   duplicate-rule-ID issue it looked like a frozen pipeline.
4. **The XML-comment API bug** — covered above under "Deploy safety
   constraints."

## Cross-links

- `converters/README.md` — Sigma→Wazuh mapping decisions and caveats.
- `../detections/wazuh/DEPLOY-NOTES.md` — the live rule-ID mapping and
  the comment-free-XML constraint.
- `../modules/detection-pipeline/docs/pipeline-demo/` — the DET-012
  canary proof of the full loop, screenshot by screenshot.
- `../shared/lessons-learned.md` — Pipeline/CD section, distilled.
