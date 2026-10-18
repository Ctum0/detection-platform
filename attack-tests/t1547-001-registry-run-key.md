# T1547.001 — Registry Run Keys / Startup Folder

Validates: [DET-013](../modules/detection-pipeline/docs/detections/det-013-registry-run-key-persistence.md)
(Wazuh rule 100021)

**Status: VALIDATED 2026-10-16. Rule 100021 verified firing on Sysmon EID 13 telemetry.**

## Preconditions

- The DET-013 rule is deployed as rule 100021 (`custom_rules.xml` contains it and the
  deploy workflow finished green).
- The Sysmon configuration on `windows-victim` logs registry value sets for
  Run keys (EID 13). Confirm with a manual test write and a look at the Sysmon
  operational log before blaming the rule.
- Atomic Red Team is installed on `windows-victim` (see the install saga in
  `../modules/adversary-emulation/docs/campaign-log.md`).

## Commands

Run as the lab user on `windows-victim`. List the tests, pick the ones that
write a value under `HKCU` or `HKLM` `...\CurrentVersion\Run` (the "Reg Key
Run" tests), and run one:

```powershell
Invoke-AtomicTest T1547.001 -ShowDetailsBrief
Invoke-AtomicTest T1547.001 -TestNumbers 1 -GetPrereqs
Invoke-AtomicTest T1547.001 -TestNumbers 1
```

Coordinate first; AV/EDR may block or alert on the write.

## Expected telemetry

Sysmon EID 13 with `TargetObject` ending in a value under `...\CurrentVersion\Run`
(or `RunOnce`), `Image` the writing process (typically `reg.exe` or
`powershell.exe`), `Details` the command written.

## Rules expected to fire

Rule 100021 (`Registry Run Key Persistence via SetValue [T1547.001]`, level 10).
Fired at level 10 on Sysmon EID 13 event.

## Cleanup

```powershell
Invoke-AtomicTest T1547.001 -TestNumbers 1 -Cleanup
```

Then confirm the Run value is gone (`reg query` on the key).

## Evidence

Alert evidence captured in `shared/evidence/det013-rule100021-alert.png` and indexed
in `shared/evidence-index.md`.

## Notes

First validation of a rule that went through the AI detection loop:
proposed by Detection Gap Analyst (PR #7), approved in Operator Console,
deployed via CI/CD (rule 100021), and validated.
