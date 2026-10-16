# T1547.001 — Registry Run Keys / Startup Folder

Validates: [DET-013](../modules/detection-pipeline/docs/detections/det-013-registry-run-key-persistence.md)
(Wazuh rule ID assigned by convert-deploy, expected 100021)

**Status: procedure only. This test has not been run. No results or evidence
exist for it yet.**

## Preconditions

- The DET-013 rule is deployed (`custom_rules.xml` contains it and the
  deploy workflow finished green); note its actual rule ID.
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
Invoke-AtomicTest T1547.001 -TestNumbers <n> -GetPrereqs
Invoke-AtomicTest T1547.001 -TestNumbers <n>
```

Coordinate first; AV/EDR may block or alert on the write.

## Expected telemetry

Sysmon EID 13 with `TargetObject` ending in a value under `...\CurrentVersion\Run`
(or `RunOnce`), `Image` the writing process (typically `reg.exe` or
`powershell.exe`), `Details` the command written.

## Rules expected to fire

The DET-013 rule (Sigma level high, Wazuh level 10). Record here, after the
run: the rule ID, the alert time, and whether a stock rule also fired.

## Cleanup

```powershell
Invoke-AtomicTest T1547.001 -TestNumbers <n> -Cleanup
```

Then confirm the Run value is gone (`reg query` on the key).

## Evidence

None yet. When captured, save under `shared/evidence/det013-*.png` and index
in `shared/evidence-index.md`.

## Notes

Also the first validation of a rule that went through the AI detection loop:
after the run, record the validation against the proposal in the Operator
Console (rule ID, attack, time fired).
