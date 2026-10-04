# Detection Platform

An end-to-end detection engineering and security operations platform
that I built and operate solo: attacks executed in a controlled lab,
telemetry flowing into a dual-SIEM stack, detections managed as code
with CI/CD, purple-team validation against real attack execution, and —
as the platform grows — a threat-intelligence feedback loop and
analyst-augmented SOAR closing the loop back to human decision.
Organized as a monorepo: one folder per module, with the detection
library, attack-test library, and pipeline tooling shared across all of
them at the platform level.

## Getting started

```bash
git clone git@github.com:Ctum0/detection-platform.git
cd detection-platform
```

## Lifecycle

```text
Attack (Parrot / Atomic Red Team)
  |
  v
Victims (Win10 + Sysmon, Ubuntu + auditd)     [Proxmox VMs]
  |
  v
Wazuh agents (TLS, port 1514)
  |
  v
Wazuh Manager (VPS, docker single-node)  -->  Wazuh Indexer + Dashboard
  |                        |
  |                        +--> (planned) Splunk forwarding
  v
Detections (Sigma as code -> CI -> convert -> CD -> Wazuh)
  ^   AI loop: Detection Gap Analyst (n8n) drafts a Sigma PR ->
  |   Operator Console human approve/reject -> merge
  v
Alerts -> SOAR (n8n): filter -> dedup -> AbuseIPDB -> AI triage ->
Telegram -> human decision; Investigation (Threat Hunting)
  |
  v
(planned) Threat intel feedback (honeypots, MISP/OpenCTI) -> detections
```

Full platform architecture (network, hosts, remote access) is in
`shared/architecture.md`.

## Modules

| Module | Focus | Status |
|---|---|---|
| [Detection Pipeline](modules/detection-pipeline/README.md) | Sigma→CI/CD→Wazuh, 13 rules (1 AI-proposed), 9 validated | ✅ Complete |
| [Adversary Emulation](modules/adversary-emulation/README.md) | ART campaign, purple-team loop; AD domain phase (planned) | 🔨 Workstream 1 complete · AD phase planned |
| [Cloud & Identity Security](modules/cloud-identity/README.md) | Entra ID / AWS monitoring, IaC scanning | 🗓 Planned |
| [SOAR & Automated Response](modules/soar/README.md) | Wazuh alerts → n8n pipeline → enrichment → AI triage → Telegram, human-in-the-loop | ✅ Complete |
| [Threat Intelligence](modules/threat-intel/README.md) | Honeypots (Cowrie/T-Pot), MISP/OpenCTI, IOC feedback into Detection Pipeline | ⬜ Not started |

The Detection Pipeline module's 9/13 is the actual current count — see
Metrics below for exactly which four are not yet validated and why.

## Platform architecture

```text
                    modules/
   (Detection Pipeline complete, Adversary Emulation Workstream 1
              complete, the other three not started)
                         |
         each module's own docs/ (matrix, campaign
         logs, per-detection writeups — genuinely
         module-specific content only)
                         |
      -------------------+-------------------
      |                  |                  |
 detections/        attack-tests/       platform/
 (Sigma source    (one writeup per   (converters/,
 of truth, Wazuh   validated          pipelines/,
 + generated       technique — the    workflows-docs.md
 Splunk SPL)        module bridge)     — shared tooling)
      |                  |                  |
      -------------------+-------------------
                         |
                     shared/
      (architecture, vm-inventory, evidence,
              evidence-index, lessons-learned)
```

`detections/`, `attack-tests/`, and `platform/` are cross-module
resources at the repo root, not owned by any single module — Detection
Pipeline authors into `detections/` and `platform/`, Adversary Emulation
authors into `attack-tests/` (and both consume `shared/`). This is
deliberate: a new module never needs its own copy of the Sigma pipeline
or its own evidence index, it just plugs into what's already here.

## How to add a detection

1. Write the rule in `detections/sigma/<name>.yml` (Sigma spec v2.1; run
   `sigma check` locally before pushing).
2. Push — CI validates and auto-generates the Splunk SPL.
3. Run `platform/converters/sigma_to_wazuh.py` to regenerate
   `custom_rules.xml`, hand-review the diff against the live Wazuh
   ruleset (see `platform/converters/README.md` for mapping decisions and
   caveats), then push — CD deploys and restarts the manager. Full
   CI/CD mechanics: `platform/workflows-docs.md`.
4. Add a per-detection doc in
   `modules/detection-pipeline/docs/detections/det-NNN-<slug>.md`
   (template: header table, Logic, Expected telemetry, Validation method,
   FP notes, Investigation guidance) and a row in
   `modules/detection-pipeline/docs/attack-matrix.md`.
5. Validate it: build a writeup in `attack-tests/`, run the attack,
   capture evidence into `shared/evidence/`, index it in
   `shared/evidence-index.md`, and flip the det-doc + matrix status to
   VALIDATED.

## Adding a module

Add a folder under `modules/` with a `README.md` (purpose, scope,
status) and a row in the table above. Nothing else changes — it reads
from `detections/`, `attack-tests/`, `platform/`, and `shared/` the same
way Detection Pipeline and Adversary Emulation already do.

## Metrics

- **Detections:** 13 (DET-001…DET-013) across 11 ATT&CK techniques — see
  `modules/detection-pipeline/docs/attack-matrix.md`
- **Validated:** 9/13 (DET-001, DET-002, DET-003, DET-004, DET-005,
  DET-006, DET-007, DET-011, DET-012)
- **Untested:** DET-008/DET-009 — blocked by an auditd ingestion gap (see
  `modules/detection-pipeline/docs/known-limitations.md`); DET-010 —
  manual deployment only (temporal correlation, no Wazuh equivalent)
- **Pending:** DET-013 — first AI-proposed rule (T1547.001), merged
  2026-10-04 after human review; awaiting its Wazuh deploy and ART run
- **Sigma rules:** 13 files (spec v2.1, `sigma check` clean)
- **Wazuh rules:** 14 custom rules — 12 converted from Sigma (IDs
  100001–100012) and 2 hand-written tuning rules (100013, 100020). New
  Sigma rules are converted and deployed by `convert-deploy.yml`
- **Splunk SPL:** 12 auto-generated searches (DET-010 excluded)
- **AI detection loop:** Detection Gap Analyst (n8n) drafts a Sigma rule
  and PR → Operator Console (human gate, merges only on green CI) →
  convert-deploy → Wazuh
- **SOAR pipeline:** 9 n8n nodes, Wazuh alert to Telegram in roughly 2–3
  minutes (most of it the AI step), with cross-execution deduplication via
  the Remove Duplicates node. Module doc: `modules/soar/README.md`.
- **Evidence:** indexed in `shared/evidence-index.md`, files in
  `shared/evidence/`

Distilled lessons from building this (Sigma/spec, Wazuh rules, Pipeline/CD,
Telemetry, ART) are in `shared/lessons-learned.md`.

## Repo layout

```text
detection-platform/
├── README.md
├── modules/
│   ├── detection-pipeline/
│   │   └── docs/                ← attack-matrix, per-detection writeups,
│   │                               pipeline-demo, known-limitations
│   ├── adversary-emulation/
│   │   └── docs/                ← campaign-log.md
│   ├── cloud-identity/          ← README only (not started)
│   ├── soar/                    ← README, workflow-export.json, docs/war-story.md
│   └── threat-intel/            ← README only (not started)
├── platform/
│   ├── converters/              ← sigma_to_wazuh.py, merge_wazuh_rules.py, wazuh_rule_ids.json
│   ├── pipelines/               ← Sigma conversion pipeline configs
│   └── workflows-docs.md        ← how CI + CD actually work
├── shared/
│   ├── architecture.md          ← platform-wide network/hosts/data flow
│   ├── vm-inventory.md          ← VM & asset inventory
│   ├── evidence/                ← screenshot evidence (every module)
│   ├── evidence-index.md        ← screenshot index
│   └── lessons-learned.md       ← distilled lessons across modules
├── detections/
│   ├── sigma/                   ← source of truth (13 rules)
│   ├── wazuh/                   ← custom_rules.xml, DEPLOY-NOTES.md
│   └── splunk/                  ← CI-generated *.spl (never hand-edited)
├── attack-tests/                ← one writeup per validated technique
└── .github/workflows/           ← CI: validate + SPL autogen; convert Sigma→Wazuh; CD: Wazuh deploy
```

## Author

Ctum0 (sithumsryt@gmail.com)
