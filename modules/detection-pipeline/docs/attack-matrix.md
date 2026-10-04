# Attack matrix

All 13 detections: technique → data source → artifacts → status.
Per-detection writeups live in `docs/detections/det-*.md`; screenshot
evidence is indexed in `shared/evidence-index.md`.

| ID | Technique | Tactic | Data source | Sigma file | Wazuh rule | SPL file | Status | Notes |
|---|---|---|---|---|---|---|---|---|
| DET-001 | T1110.001 Password Guessing | Credential Access | auth.log (sshd) via Wazuh agent | `ssh_bruteforce.yml` | 100008 (base) + 100009 (freq 6/10m); stock 5712 | `ssh_bruteforce.spl` | VALIDATED 2026-09-26 | Hydra burst → stock 5712 fired |
| DET-002 | T1059.001 PowerShell | Execution | Sysmon EID 1 via Wazuh agent | `powershell_encoded_command.yml` | 100005 | `powershell_encoded_command.spl` | VALIDATED 2026-09-27 | Custom 100005 fired lvl 10; attack screenshot not yet captured. Alert also validated end to end into the SOAR triage pipeline (see `modules/soar/`) |
| DET-003 | T1059.001 PowerShell | Execution | Sysmon EID 1 via Wazuh agent | `powershell_download_cradle.yml` | 100004 | `powershell_download_cradle.spl` | VALIDATED 2026-09-27 | ART W1: DownloadString+IEX cradle → 100004 fired lvl 10 |
| DET-004 | T1003.001 LSASS Memory | Credential Access | Sysmon EID 10 via Wazuh agent | `lsass_credential_dumping.yml` | 100003 | `lsass_credential_dumping.spl` | VALIDATED 2026-09-27 | ART W1 T1003.001 (comsvcs.dll MiniDump) → EID 10, custom 100003 fired ×2. Stock 92900 still observed on benign svchost reads (the FP case 100003 excludes) |
| DET-005 | T1136.001 Local Account | Persistence | Windows Security 4720 via Wazuh agent | `local_user_creation.yml` | 100002 | `local_user_creation.spl` | VALIDATED 2026-09-27 | `net user backdoor` → 60109 + EID 4722 observed. |
| DET-006 | T1053.005 Scheduled Task | Persistence | Windows Security 4698 via Wazuh agent | `scheduled_task_creation.yml` | 100006 (chains stock 60228) | `scheduled_task_creation.spl` | VALIDATED 2026-09-27 | Custom 100006 fired lvl 7 after manager restart; attack screenshot not yet captured |
| DET-007 | T1543.003 Windows Service | Persistence | Windows System 7045 via Wazuh agent | `suspicious_service_creation.yml` | 100011 | `suspicious_service_creation.spl` | VALIDATED 2026-09-27 | ART W1: `sc create` with binary_path under `C:\Temp\` → 7045, 100011 fired. ART's own default path (`C:\AtomicRedTeam\...`) correctly did NOT fire — pattern list is threat-model-based, not test-based |
| DET-008 | T1548.001 Setuid and Setgid | Privilege Escalation | Linux auditd EXECVE via Wazuh agent | `suid_privilege_escalation.yml` | 100010 | `suid_privilege_escalation.spl` | UNTESTED — BLOCKED, L-001 abandoned | Rule deployed but unvalidated. Linux auditd ingestion abandoned after reboot retry failed (conscious decision, see `docs/known-limitations.md` L-001). Execve telemetry is captured locally via `ausearch` only |
| DET-009 | T1059.004 Unix Shell | Execution | Linux auditd EXECVE via Wazuh agent | `linux_reverse_shell.yml` | 100001 | `linux_reverse_shell.spl` | UNTESTED — BLOCKED, L-001 abandoned | Rule deployed but unvalidated. Linux auditd ingestion abandoned after reboot retry failed (conscious decision, see `docs/known-limitations.md` L-001). Execve telemetry is captured locally via `ausearch` only |
| DET-010 | T1110.001 Password Guessing | Credential Access | auth.log (sshd), temporal correlation | `ssh_success_after_failures.yml` | SKIP (temporal_ordered unsupported) | — (excluded from SPL autogen) | UNTESTED | Manual deployment only; needs parsed `src_ip`; not part of W1 scope |
| DET-011 | T1685.005 Clear Windows Event Logs | Defense Impairment | Windows Security 1102 via Wazuh agent | `security_log_cleared.yml` | 100007 (parent fixed to `if_sid 63103`) | `security_log_cleared.spl` | VALIDATED 2026-09-27 | `wevtutil cl Security` → 1102, 100007 fired after parent-ID fix (was `if_group windows_security`, never fired); MITRE restructured 2026: ex-T1070.001 |
| DET-012 | T1098 (canary) | Execution | Sysmon EID 1 via Wazuh agent | `notepad_execution.yml` | 100012 | `notepad_execution.spl` | VALIDATED 2026-09-27 | Pipeline canary: commit -> CI -> deploy -> notepad run -> alert; see `docs/pipeline-demo/` |
| DET-013 | T1547.001 Registry Run Keys / Startup Folder | Persistence | Sysmon EID 13 (registry_set) via Wazuh agent | `t1547_001_registry_run_key_persistence_via_setvalue.yml` | assigned by convert-deploy on first run (expected 100021) | `t1547_001_registry_run_key_persistence_via_setvalue.spl` | MERGED 2026-10-04 — pending Wazuh deploy + ART validation | First AI-proposed rule: Detection Gap Analyst draft, PR #7, approved in the Operator Console after logic review |

Coverage: 11 distinct techniques across Credential Access, Execution,
Persistence, Privilege Escalation and Defense Impairment. 9/13 validated —
ART Workstream 1 (Windows campaign, see
`../../adversary-emulation/docs/campaign-log.md`) closed out DET-003,
DET-004, DET-007 and DET-011 on 2026-09-27. DET-008/DET-009 remain
blocked by the auditd ingestion gap (L-001); DET-010 is manual-deployment
only and was out of scope for W1.
