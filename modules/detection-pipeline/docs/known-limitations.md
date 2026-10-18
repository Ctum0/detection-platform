# Known limitations

## L-001: auditd EXECVE telemetry on linux-victim (closed — resolved by removal)

L-001 (closed — resolved by removal). The Linux auditd EXECVE telemetry path on linux-victim was abandoned (auditd died 2026-09-26; systemd restart rate-limit + lingering kauditd; a reboot did not recover it). Rather than ship two rules that could never be validated, DET-008 and DET-009 were removed. The full forensic trail is in the git history.

---

## L-002: built-in rule 92213 fires on PowerShell policy-test artefacts (resolved)

PowerShell writes `__PSScriptPolicyTest_*.ps1` files into the user's Temp
directory on every session start. Wazuh's built-in Temp-drop rule (92213)
fires on each one, which produced hundreds of alerts per day with no signal.

**Resolution:** rule 100020, a level-0 child of 92213, matches the
`__PSScriptPolicyTest_*.ps1` filename and suppresses the alert.

**Result:** before the rule, hundreds of 92213 alerts per day from this
source; after it, zero. Genuine Temp-drop detections were unaffected.

The rule and its reasoning are in `docs/tuning/fp-suppressions.md`.

---

## L-003: stray `local_rules.xml.bak` in the rules directory (resolved)

A backup file `local_rules.xml.bak` sat inside `/var/ossec/etc/rules/`.
`analysisd` loads every XML file in that directory, so the backup could
redefine custom rules alongside the live file. It was the same class of
problem as the duplicate-rule-ID bug in the pipeline demo.

**Resolution:** the backup file was removed from the rules directory.
