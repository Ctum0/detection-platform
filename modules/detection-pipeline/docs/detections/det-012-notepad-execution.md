# DET-012 — Notepad Execution (CI/CD Canary)

| Field | Value |
|---|---|
| Detection ID | DET-012 |
| Rule | Sigma `detections/sigma/notepad_execution.yml`; Wazuh 100012; SPL `detections/splunk/notepad_execution.spl` |
| Data source | Sysmon EID 1 via Wazuh agent |
| ATT&CK | T1098 (Persistence), used only as a placeholder technique for the canary |
| Severity | Low |
| Status | VALIDATED 2026-09-27 |

## Logic

`Image endswith \notepad.exe`. Rule 100012 is level 5, below the SOAR alert threshold of 8, so it
does not page. Trivial by design: notepad is harmless and
trivially triggerable, so what is being tested is the pipeline itself
(Sigma → CI → deploy → alert), not the detection logic.

## Expected telemetry

Sysmon EID 1 with `Image: C:\Windows\System32\notepad.exe` on windows-victim.

## Validation method

Run `notepad.exe` on the victim; confirm EID 1 ships and rule 100012 fires.

Validated 2026-09-27 (SIEM side): custom rule 100012
`Detection Platform: Notepad execution - CI/CD pipeline test [T1098]` fired on
windows-victim. Full loop (commit `8255cd9` → validate green → deploy
green → attack → alert) documented with screenshots in
`docs/pipeline-demo/` (`01-sigma-rule.png` … `05-alert-100012.png`).

## FP notes

Any user opening Notepad fires this — expected; it is a canary, not a
threat detection. Never alert-page on it.

## Investigation guidance

None needed beyond confirming the process launch was the planned test.
If 100012 fires outside a planned pipeline test, treat the host as
potentially interactively accessed and investigate logons (4624).
