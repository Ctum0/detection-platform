# Lessons Learned

Distilled lessons from building the [Detection Pipeline](../modules/detection-pipeline/README.md)
module and the [Adversary Emulation](../modules/adversary-emulation/README.md)
module (ART-driven validation), grouped by area. Each entry links back to
the detection doc, campaign log or pipeline-demo writeup where it was
found in detail.

## Sigma / spec

- **Pin the Sigma spec version and enforce it in CI.** All rules target
  Sigma spec v2.1 with `attack.tXXXX.XXX` + hyphenated tactic tags (e.g.
  `attack.credential-access`); `sigma check` runs on every push touching
  `detections/sigma/**` and must stay at zero errors before anything else
  in the pipeline is trusted. Catching spec drift at the rule-authoring
  stage is far cheaper than catching it after a bad rule has already gone
  through conversion and deploy.
- **ATT&CK itself drifts — resolve tactic/technique names from the rule's
  own tags, not a static table.** MITRE restructured log-clearing in 2026:
  the old T1070.001 (Indicator Removal) became T1685.005 (Disable or
  Modify Tools: Clear Windows Event Logs) under a renamed tactic
  ("Defense Impairment"). The Sigma→Wazuh converter resolves tactic
  display names from each rule's own tags first, falling back to a static
  table only if the tag isn't present — so restructures like this flow
  through automatically instead of silently mislabeling MITRE fields on
  every future regeneration. See
  `../platform/converters/sigma_to_wazuh.py` (the
  `tactic_of` function and its MITRE table comment) and
  [DET-011](../modules/detection-pipeline/docs/detections/det-011-security-log-cleared.md).

## Wazuh rules

- **Verify a rule's actual decoded parent — don't assume from the channel
  or event category.** DET-011 (rule 100007) was authored on
  `<if_group>windows_security</if_group>` on the reasonable-looking
  assumption that a Security-channel event would chain off that group.
  In fact EventID 1102 decodes under the specific stock parent rule
  **63103**, not the generic group, so the rule silently never fired —
  no error, just no alerts. This happened twice in the same campaign
  (same class of mistake, different rule) before the team adopted a
  standing rule: **run `wazuh-logtest` against a captured/synthetic event
  and confirm the actual parent SID before anchoring any new rule on
  `if_sid`/`if_group`**, rather than inferring the parent from what seems
  plausible. See
  `../modules/detection-pipeline/docs/detections/det-011-security-log-cleared.md`
  and `../modules/adversary-emulation/docs/campaign-log.md`.
- **Sysmon anchoring is version-sensitive.** Wazuh 4.9.0 broke `if_sid`
  chaining off level-0 Sysmon parents at runtime (wazuh/wazuh#36029) —
  `if_group` (`sysmon_event1` / `sysmon_event_10`) is the robust anchor on
  4.9.0+ and is what this repo's rules use. Worth re-checking on every
  Wazuh upgrade, since anchor behavior like this isn't always called out
  in release notes. See
  `../platform/converters/README.md` (Caveats).
- **A rule correctly *not* firing is a valid, worth-documenting outcome.**
  DET-007's pattern list (suspicious service binary paths) is
  threat-model-based, not test-based — Atomic Red Team's own default
  install path (`C:\AtomicRedTeam\...`) doesn't match it and correctly
  produced no alert. The instinct to keep tweaking a rule until it fires
  on every test run is wrong when the test's default behavior isn't
  actually representative of the threat; the fix was to make the test
  input realistic (`-PromptForInputArgs`, binary staged under `C:\Temp\`),
  not to loosen the rule. See
  `../attack-tests/t1543-003-service-creation.md`.

## Pipeline / CD

- **An API 200 does not mean the change is live — verify the actual
  runtime state, not just the write.** The CD workflow's Wazuh API PUT
  returns HTTP 200 and `"error": 0` on a successful *file write*, but in
  this single-node docker deployment `analysisd` does not hot-reload rule
  files from a PUT alone — a manager restart is required before an
  edited or new rule actually takes effect. This produced a genuinely
  confusing debugging session (parent-ID fix looked "deployed" but the
  rule still didn't fire) before the root cause was found. Fixed by
  adding an explicit `docker restart single-node-wazuh.manager-1` step
  (plus an agent-connectivity check) after every deploy. This generalizes
  beyond this one incident: **a green CD step proves the artifact was
  written, not that the running system picked it up** — verify the
  runtime, not just the API response, whenever a deploy step's job is to
  change live behavior. See
  `../modules/detection-pipeline/docs/pipeline-demo/README.md`
  (debugging war story) and `.github/workflows/deploy-wazuh.yml`.
- **Silent-success failure modes are worse than loud failures.** The
  original deploy step ran `curl -s` without checking the status code, so
  it swallowed HTTP errors and exited 0 — a workflow can show fully green while the manager is still
  running stale rules. Fixed by capturing the HTTP code explicitly and
  failing the step on anything but 200 + `error: 0`. Same principle as
  the hot-reload lesson above: a CI/CD step should fail loudly the moment
  it can't prove the thing it claims to have done actually happened.

## Telemetry

- **A stale artifact/log file is itself a symptom worth checking before
  chasing a forwarding or decoding theory.** The auditd ingestion gap
  (L-001) was initially investigated as a collection/decoding problem —
  plausible, since the manager-side decoders and agent config are
  genuinely complex enough to hide a real bug there. The actual root
  cause was much simpler: `auditd` on `linux-victim` had died (its
  `audit.log` was stale with a `DAEMON_END` record from hours earlier),
  and systemd's restart rate-limiter plus a lingering `kauditd` kernel
  thread were preventing a clean in-place recovery. **Check whether the
  producer is even alive and its output is current before investigating
  the pipe.** See
  `../modules/detection-pipeline/docs/known-limitations.md` (L-001).
- **A downstream execution boundary can be inherent to a technique, not a
  gap in logging coverage.** The PowerShell download-cradle test
  (T1059.001, DET-003) fetches and executes its payload entirely
  in-memory — `DownloadString`+`IEX` never touches disk, so Sysmon EID
  1's `CommandLine` field is the *only* telemetry surface for this
  specific technique; there's no file-creation event to fall back on if
  process-creation logging were ever degraded. Worth calling this out
  explicitly in the detection's own documentation rather than assuming
  "another control will catch it" — for this technique, there usually
  isn't one. See
  `../modules/adversary-emulation/docs/campaign-log.md` ("The in-memory
  cradle lesson").

## ART

- **Installer friction on a hardened default image is expected, budget
  time for it.** Standing up Atomic Red Team on `windows-victim` hit disk
  space limits, PowerShell execution-policy blocks, and confusion between
  the bootstrap installer script and the `Invoke-AtomicRedTeam` module it
  installs — none of which are ART bugs, all of which cost real
  debugging time on a first install. See
  `../modules/adversary-emulation/docs/campaign-log.md` ("The ART
  install saga").

## SOAR build lessons (Module 4)

- **n8n: multiple inbound connections mean one execution per branch, not an
  input merge.** A node with two incoming wires runs once for each. In this
  build that duplicated every downstream side effect, including the Telegram
  send. Fix by making the join a run-once node that reads its other inputs
  explicitly. See [war story §7](../modules/soar/docs/war-story.md).
- **n8n: in-memory `staticData` has no atomicity.** Two executions arriving
  in the same millisecond both pass a check. Use the database-backed Remove
  Duplicates node for cross-execution dedup.
- **Remove Duplicates "Value Is New" remembers forever.** For a rate window,
  bucket the key, for example `rule_id` plus the minute. Otherwise the first
  alert for a rule silently blocks every later one.
- **Wazuh integrations need a matching script or a native name.** A
  `custom-*` integration without a script in `/var/ossec/integrations/` is
  skipped without an error. Native names such as `shuffle`, `slack` and
  `pagerduty` avoid this.
- **Container config lives on the volume.** In single-node docker, edits to
  the host bind-mount do not reach the running manager. Confirm which file
  the process reads before checking the contents.
- **"Tiny test prompt works" is not "production prompt works".** A health
  check with a short input passed for a model that hung on the real triage
  prompt. Test with production-sized inputs, and set explicit timeouts on
  every model call, because a model can hang rather than fail.
- **Synthetic tests can pass for the wrong reason.** The double-send only
  appeared when every input branch delivered data, which synthetic payloads
  never did. Test end to end with real attacks.
