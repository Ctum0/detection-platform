# Detection Pipeline

**Status: COMPLETE** (DET-013 deployed, validation pending) — ART campaign complete for
Windows; 9/13 detections have a recorded attack run and alert, Sigma → CI →
convert → CD → Wazuh pipeline proven live. Validation caveats are listed
under Validated rules below.

Detection engineering as code: Sigma rules are the source of truth,
CI validates them and generates Splunk SPL, a convert step merges new rules
into the Wazuh rule file, CD deploys that file to the live manager, and each
detection is proven by running the attack it is built to catch.

## Layout

```text
detection-pipeline/
└── docs/
    ├── attack-matrix.md      ← all 13 detections at a glance
    ├── detections/           ← one doc per detection (det-001...det-013)
    ├── tuning/               ← false-positive suppression notes
    ├── pipeline-demo/        ← DET-012 end-to-end CI/CD walkthrough
    ├── ai-detection-loop.md  ← Detection Gap Analyst, sigma-validator, console
    └── known-limitations.md  ← open gaps (auditd ingestion, L-001)
```

This module authors into three platform-level shared resources rather
than owning them outright — `detections/` (Sigma source of truth, Wazuh
rules, generated SPL), `platform/converters/` (the Sigma→Wazuh converter),
and `platform/pipelines/` (Sigma conversion pipeline configs) all live at
the repo root, since the Adversary Emulation module's attack tests
validate against the same `detections/` tree. Only the write-ups
genuinely specific to this module — the matrix, per-detection docs, the
pipeline demo, known limitations — live under its own `docs/`.

## Architecture

```text
detections/sigma/*.yml  (source of truth, hand-authored)
        |
        |  push
        v
CI: sigma check  ->  sigma convert -t splunk  ->  detections/splunk/*.spl
        |                                          (auto-committed)
        |  workflow_run after CI succeeds on main
        v
Convert (convert-deploy.yml): sigma_to_wazuh.py + merge_wazuh_rules.py
  -> new rules appended to custom_rules.xml, committed, CD dispatched
        |
        |  push touching custom_rules.xml, or dispatch
        v
CD (self-hosted runner, co-located with the Wazuh manager):
  PUT detections/wazuh/custom_rules.xml -> Wazuh API
        -> restart manager (PUT alone doesn't hot-reload)
        -> verify every rule ID in the file is reported via GET
        |
        v
Wazuh Manager (live) -> alert fires when the attack it targets runs
```

Full CI/CD mechanics, including the hot-reload bug that made the restart
step necessary, are in `../../platform/workflows-docs.md`.

## Pipeline

1. Author/edit rules in `detections/sigma/` (Sigma spec v2.1, ATT&CK tags
   `attack.tXXXX.XXX` + hyphenated tactic names — `sigma check` must stay
   clean).
2. CI (`Validate Sigma rules`) runs `sigma check` on every push touching
   `detections/sigma/**`.
3. CI auto-generates Splunk SPL via `sigma convert -t splunk
   --without-pipeline` into `detections/splunk/`, committed back
   automatically (`[skip ci]`, push only).
4. Convert (`Convert Sigma to Wazuh and deploy`) runs after CI succeeds on
   `main`: it converts the Sigma rules, merges only new ones into
   `custom_rules.xml` (existing rules, including hand-tuning, are kept),
   commits and dispatches CD. It never updates an existing rule when its
   Sigma changes; it reports the difference as drift and leaves the live
   rule as it is.
5. CD (`Deploy rules to Wazuh`, self-hosted runner) PUTs
   `detections/wazuh/custom_rules.xml` to the manager API on every push
   touching it, restarts the manager (single-node docker does not
   hot-reload rule files on PUT — see `docs/known-limitations.md` /
   `shared/lessons-learned.md`), then verifies HTTP 200 and that every rule
   ID in the file is reported back. Proven end-to-end by DET-012, see
   `docs/pipeline-demo/`.
6. `ssh_success_after_failures.yml` is excluded from SPL conversion: its
   `temporal_ordered` correlation is unsupported by the Splunk backend.

## Validated rules

| DET | Technique | Wazuh rule | Status |
|---|---|---|---|
| DET-001 | T1110.001 Password Guessing | 100008/100009 (+ stock 5712) | VALIDATED via stock 5712 only; custom 100008/100009 not shown firing |
| DET-002 | T1059.001 PowerShell (encoded command) | 100005 | VALIDATED |
| DET-003 | T1059.001 PowerShell (download cradle) | 100004 | VALIDATED |
| DET-004 | T1003.001 LSASS Memory | 100003 | VALIDATED per campaign log; rule 100003 firing screenshot not captured |
| DET-005 | T1136.001 Local Account | 100002 | VALIDATED via stock 60109/60110 and EID 4722; custom 100002 firing not shown in indexed evidence |
| DET-006 | T1053.005 Scheduled Task | 100006 | VALIDATED |
| DET-007 | T1543.003 Windows Service | 100011 | VALIDATED |
| DET-008 | T1548.001 Setuid and Setgid | 100010 | UNTESTED — blocked, L-001 abandoned |
| DET-009 | T1059.004 Unix Shell | 100001 | UNTESTED — blocked, L-001 abandoned |
| DET-010 | T1110.001 Password Guessing (temporal) | — (manual only) | UNTESTED — out of scope |
| DET-011 | T1685.005 Clear Windows Event Logs | 100007 | VALIDATED |
| DET-012 | T1098 (CI/CD canary) | 100012 | VALIDATED |
| DET-013 | T1547.001 Registry Run Keys | 100021 | DEPLOYED 2026-10-16 — ART run not yet recorded |

Full detail per row: `docs/attack-matrix.md`. Per-detection writeups
(logic, expected telemetry, FP notes, validation evidence):
`docs/detections/`.

## Metrics

- **Detections:** 13 (DET-001...DET-013) across 11 ATT&CK techniques —
  see `docs/attack-matrix.md`
- **Validated:** 9/13 — DET-001, DET-002, DET-003, DET-004, DET-005,
  DET-006, DET-007, DET-011, DET-012
- **Untested:** DET-008, DET-009 (blocked by the auditd ingestion gap,
  `docs/known-limitations.md` L-001), DET-010 (manual-deployment only,
  temporal correlation has no Wazuh equivalent)
- **Pending:** DET-013 (T1547.001, first AI-proposed rule) — merged
  2026-10-04, deployed as rule 100021 on 2026-10-16; it still needs an ART run
- **Sigma rules:** 13 files, spec v2.1, `sigma check` clean
- **Wazuh rules:** 15 custom rules in `custom_rules.xml` — 13 converted
  from Sigma (IDs 100001-100012 and 100021) plus hand-written level-0 suppression rules
  100013 and 100020; new Sigma rules are converted and deployed by
  `convert-deploy.yml`
- **Splunk SPL:** 12 auto-generated searches (DET-010 excluded)
- **Evidence:** indexed in `shared/evidence-index.md`, files in
  `shared/evidence/`

## Related

- [Adversary Emulation](../adversary-emulation/README.md) — the attack
  side that validates these detections (ART campaigns, per-technique
  writeups)
- `shared/architecture.md` — platform-wide data flow
- `shared/lessons-learned.md` — distilled lessons from building this
