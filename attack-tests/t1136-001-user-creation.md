# T1136.001 — Local Account Creation

Validates: [DET-005](../modules/detection-pipeline/docs/detections/det-005-local-user-creation.md)
(Wazuh custom 100002)

## Commands

Run as admin on `windows-victim`:

```powershell
net user backdoor P@ssw0rd123 /add
```

## Expected telemetry

Security EID 4720 (`A user account was created`) with `TargetUserName` =
`backdoor` and `SubjectUserName` = the operator.

## Rules fired

- Stock 60109 `User account enabled or created`.
- Stock 60110 `User account changed`.
- Security EID 4722 `A user account was enabled` — Target `backdoor`,
  Subject set to the operator account.
- Supporting: 92039 (net.exe execution) / 92033 (PowerShell discovery)
  observed alongside.
- Custom Wazuh rule 100002 `Detection Platform: Local user account created (4720)
  [T1136.001]`.

## Cleanup

```powershell
net user backdoor /delete
```

## Notes

Ran as a manual `net user` command rather than a named ART test (no AD in
the lab, so every 4720 is local-account creation on the Win10 victim by
definition). Alerts observed were stock rules 60109/60110 and EID 4722;
custom rule 100002 firing is not evidenced. Planned screenshots
(`shared/evidence/det005-*.png`) are not in the repo; see
`shared/evidence-index.md`.
