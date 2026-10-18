# DET-013 — Registry Run Key Persistence via SetValue

| Field | Value |
|---|---|
| Detection ID | DET-013 |
| Rule | Sigma `detections/sigma/t1547_001_registry_run_key_persistence_via_setvalue.yml`; Wazuh rule 100021 (deployed 2026-10-16 by convert-deploy); SPL `detections/splunk/t1547_001_registry_run_key_persistence_via_setvalue.spl` |
| Data source | Sysmon EID 13 (RegistryEvent, value set) via Wazuh agent |
| ATT&CK | T1547.001 — Registry Run Keys / Startup Folder |
| Severity | High (Sigma level `high`; converts to Wazuh level 10) |
| Status | VALIDATED 2026-10-16 — Rule 100021 fired on Sysmon EID 13 (`shared/evidence/det013-rule100021-alert.png`) |

## Origin

First rule proposed by the Detection Gap Analyst (n8n) and approved in the
Operator Console after logic review. See `../ai-detection-loop.md`. The
Sigma file was later edited by hand (author, date and references added, a
proper UUID id, and the msiexec exclusion restricted to its System32 and
SysWOW64 paths, so an `msiexec.exe` copied elsewhere still alerts).

## Logic

`TargetObject` contains `\Microsoft\Windows\CurrentVersion\Run`,
`\RunOnce` or `\RunServices` AND the writing `Image` is not one of the
allowlisted installer or system binaries (msiexec in System32/SysWOW64,
`WMUNOTIFY.EXE`, `TMMREGISTRY.EXE`). Single-event rule. The last two
exclusions are name-only and are still to be reviewed against lab telemetry.

## Expected telemetry

Sysmon EID 13 with `TargetObject` under a Run key (for HKCU writes this
appears as `HKU\<SID>\Software\Microsoft\Windows\CurrentVersion\Run\<name>`),
`Details` holding the command, and `Image` naming the process that wrote it.
Check before testing that the deployed Sysmon configuration actually logs
registry value sets for Run keys; if it does not, no rule can fire.

## Validation method

Validated on 2026-10-16. Rule 100021 deployed on Wazuh Manager. Sysmon EID 13
event (SetValue on `HKLM\Software\Microsoft\Windows\CurrentVersion\Run\AtomicTest`
by `powershell.exe`) processed by Wazuh engine; rule 100021 fired with Level 10
(T1547.001). See evidence screenshot in `shared/evidence/det013-rule100021-alert.png`.

## FP notes

Installers, uninstallers and updaters write Run keys routinely; so do
endpoint agents and configuration tools. Expect noise on first deploy and
tune by `Image` and `Details` after baselining. Do not widen the name-only
exclusions without checking the signer.

## Investigation guidance

1. Which process wrote the value (`Image`, parent, command line)? Is it signed?
2. What does `Details` point to? Does the binary exist, and where (Temp,
   AppData, ProgramData are the usual staging places)?
3. Who was logged on, and what else did that session do around the same time?
4. Check the same user's other autostart locations (RunOnce, Startup folder,
   scheduled tasks, services).
