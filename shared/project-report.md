# Project report

State of the platform as of 2026-10-16, written after a full audit of
the repository, the operator console repository, and the read-only
inspection of the live deployment. Every claim here was checked against
the code, CI runs, or the running system; things that were not checked
are listed under "Not verified".

## 1. What it is

A detection engineering platform run by one person on a home lab plus a
VPS. Attacks are executed against instrumented victims, telemetry reaches
Wazuh, detections are written as Sigma, validated and converted by CI, and
deployed to Wazuh by CD. An AI loop proposes new detections, and a human
approves each one in a web console before it is merged.

## 2. Components

| Component | Where | Role |
|---|---|---|
| Attack and victim lab | Proxmox: Parrot attacker, Windows 10 with Sysmon, Ubuntu with auditd | Executes Atomic Red Team tests and produces telemetry |
| Wazuh 4.14.8 | VPS, Docker single node (manager, indexer, dashboard) | SIEM, rule engine, alert store |
| Sigma library | `detections/sigma/` (13 rules) | Source of truth for detections |
| CI: Validate | `.github/workflows/validate.yml` | `sigma check`, generates Splunk SPL (12 searches) |
| CI: Platform tests | `.github/workflows/tests.yml` | 21 pytest tests for the converter, merge step and rule XML |
| Convert | `.github/workflows/convert-deploy.yml`, `platform/converters/` | Converts new Sigma rules to Wazuh XML, keeps rule IDs stable, reports drift |
| CD: Deploy | `.github/workflows/deploy-wazuh.yml` (self-hosted runner on the VPS) | Uploads `custom_rules.xml` through the Wazuh API, restarts the manager, verifies every rule ID |
| SOC Alert Triage | n8n, `modules/soar/` | Wazuh alert, level filter, dedup, AbuseIPDB, LLM triage, Telegram |
| Detection Gap Analyst | n8n | Drafts a Sigma rule, opens a PR, registers it in the console |
| Operator Console | separate repo `Ctum0/operator-console`, FastAPI plus one HTML file | Human approve/reject gate; merges only when the PR is open and CI is green |

`sigma-validator` (a small HTTP service the Gap Analyst calls) and `hermes`
run on the VPS. Their source and purpose are not documented in either
repository and are marked "owner to describe" in
`modules/detection-pipeline/docs/ai-detection-loop.md`.

## 3. Detection inventory

- 13 Sigma detections across 11 ATT&CK techniques.
- 14 custom Wazuh rules: 100001-100012 converted from Sigma, 100013 and
  100020 hand-written level-0 suppressions.
- 9 detections have a recorded attack run and alert. DET-001 and DET-005
  were proven by stock Wazuh rules, not the custom ones. DET-008 and
  DET-009 are blocked by an auditd ingestion gap. DET-010 is a temporal
  correlation with no Wazuh equivalent. DET-013 (T1547.001) was the first
  AI-proposed rule; it is merged in Sigma and becomes rule 100021 on the
  next convert-deploy run.

## 4. What the audit changed

Main repository, PR #8 (branch `audit/detections-ci-docs`):

- Rule 100003 regex was missing its closing anchor and also matched the
  benign access mask handled by 100013. Fixed.
- Rules 100001, 100008 and 100012 reconciled with their Sigma sources.
- The converter now reports drift between Sigma and the live rules, fails
  cleanly on bad YAML, and no longer adds a `<group>` tag that duplicates
  its `if_group` anchor.
- The deploy workflow verifies every rule ID, checks the API `error`
  field, masks secrets, serialises runs, and only triggers on rule-file
  changes.
- Tool versions are pinned in CI. Converter and rule-file tests added.
- Documentation counts, the evidence index, the DET-013 write-up, the
  attack test and the AI-loop description were brought in line with the
  system.

Console repository, PR #3 (branch `audit/console-hardening`):

- Merge is pinned to the commit CI checked; GitHub rejects it if the
  branch moved.
- Fresh installs start empty (the seeded sample pointed at a real PR).
- Security headers added. 117 tests and a CI workflow added.
- Edge cases fixed: corrupt data files, whitespace-only fields, bad
  filter values, invalid dates, unreachable hosts, malformed coverage
  tables.
- Chart and mobile layout defects fixed.

## 5. Live verification

Checked in a browser against the live console without triggering any
action: all six pages render with no console errors; pipeline health
reports the Wazuh API at 4.14.8 with 4,540 rules; the activity log shows
the CI gate blocking a closed PR and a PR whose checks were still running.

## 6. Known gaps

1. Neither PR is merged, so the live system still runs the old code.
2. Rules 100001, 100008 and 100021 have not been run through
   `wazuh-logtest` on a manager that has the new rules loaded.
3. The Gap Analyst failed 3 of its last 5 runs: drafts did not parse as
   Sigma, or the filter excluded the attacker tool itself. It retries once.
4. The hardened n8n workflows in `modules/soar/` are prepared but not
   imported. The live SOC workflow still holds credentials inline.
5. The SOAR webhook has no authentication; Wazuh's integration cannot send
   a custom header, so the control is network restriction.
6. `deploy-wazuh.yml` still uses `curl -k` and a hardcoded password file
   path on the runner. The pre-deploy backup lives in the job's temp
   directory, so it is not a rollback.
7. Per-detection evidence screenshots are mostly not captured (10 of 16
   rows are marked "not captured").
8. Rule 100001 no longer detects socat EXEC-style shells or `nc -e` beyond
   the first three arguments.
9. Console: a merge that times out on the console side but succeeds on
   GitHub leaves the proposal in `merge_failed`; the Agent Link status
   stays degraded after a single old failure.

## 7. Not verified

Splunk forwarding (planned only), the auditd path, end-to-end alert
latency, and the contents of `sigma-validator` and `hermes`.

## 8. Recommended order

1. Run `wazuh-logtest` for 100001, 100008 and 100021 in a throwaway
   manager container, then merge PR #8.
2. Merge console PR #3.
3. Import the hardened n8n workflows inactive, test, then swap.
4. Improve the Gap Analyst drafting prompt and retry loop.
5. Capture the missing evidence and document `sigma-validator` and
   `hermes`.
