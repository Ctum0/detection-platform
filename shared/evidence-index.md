# Evidence index

Screenshot evidence for detection validations, covering every module.
Files are expected in `shared/evidence/` under the exact filenames below.

**Reconciled against the directory.** As of this revision `shared/evidence/`
holds 10 files, listed under "Present" in the next section. Every other
filename in this index is a planned or earlier-indexed name whose file is not
in the repository. Those entries are kept for history and marked
"not captured" in the Status column; no file backs them. The pipeline demo
screenshots (`01-sigma-rule.png` to `05-alert-100012.png`) live in
`modules/detection-pipeline/docs/pipeline-demo/`, not here.

The Source column names the original local screenshot a file was to be
copied from. Those source files are outside this repository and are not
verified here. Views: **attack** = attacker/victim terminal doing the thing;
**SIEM** = Wazuh alert/event view showing the detection.

## Present in `shared/evidence/`

| File | Shows |
|---|---|
| `det002-rule100005-encoded.png` | DET-002, SIEM view of custom rule 100005 |
| `det003-rule100004-alert.png` | DET-003, SIEM view of custom rule 100004 |
| `det006-rule100006-task.png` | DET-006, SIEM view of custom rule 100006 |
| `det007-rule100011-alert.png` | DET-007, SIEM view of custom rule 100011 |
| `det011-rule100007-alert.png` | DET-011, SIEM view of custom rule 100007 |
| `det011-wevtutil-attack.png` | DET-011, attack view (ART T1685.005-4) |
| `n8n-workflow-canvas.png` | SOAR, the 9-node SOC Alert Triage workflow |
| `n8n-execution-success.png` | SOAR, one successful execution |
| `telegram-alert-triage.png` | SOAR, Telegram message for rule 100005 |
| `telegram-alert-triage-92213.png` | SOAR, Telegram message for stock rule 92213 |

What the present files prove: custom rules 100005, 100004, 100006, 100011 and
100007 each fired at least once (SIEM view), and the SOAR path delivered
messages. Nothing present shows custom rules 100002, 100003, 100008 or
100009 firing.

## Lab + SIEM overview (supporting)

| Suggested file | Source | Shows | Story fit | Status |
|---|---|---|---|---|
| `evidence/lab-endpoints-agents.png` | `Screenshot_20260926_195231.png` | Endpoints view: 2 active agents — `linux-victim` (Ubuntu 22.04.5) and `windows-victim` (Windows 10 Pro), Wazuh 4.14.8 | Lab view — proves the victim inventory behind every DET | Not captured (file not in repo) |
| `evidence/siem-threat-hunting-overview.png` | `Screenshot_20260926_195335.png` | Threat Hunting dashboard: 2,891 total alerts, 39 level-12+, 4 auth failures, 3 auth successes; alert-evolution spikes; MITRE donut incl. Password Guessing, PowerShell, Disable or Modify Too…, File Deletion, Account Discovery | SIEM view — lab is generating real technique telemetry | Not captured (file not in repo) |

## DET-001 — SSH Brute Force (validated by stock rule 5712 only)

Neither file is in the repo. The alert in the SIEM view is stock rule 5712;
custom rules 100008/100009 were not shown firing.

| Suggested file | Source | Shows | Story fit | Status |
|---|---|---|---|---|
| `evidence/det001-hydra-attack.png` | `Screenshot_20260926_195548.png` | Parrot terminal running `hydra -l nonexistentuser -P rockyou.txt -t 4 <victim-ip> ssh` (14M+ login tries queued) over a Wazuh events table streaming rule 5710 `sshd: Attempt to login using a non-existent user` | Attack view (+ SIEM context in background) | Not captured (file not in repo) |
| `evidence/det001-rule5712-bruteforce.png` | `Screenshot_20260926_200001.png` | Discover view: hydra at 76 tries/min over MPs; event table shows the 5710 stream **and** rule 5712 `sshd: brute force trying to get access to the system. Non existent user.` firing at 19:59:46 | SIEM view — the brute-force correlation firing | Not captured (file not in repo) |

## DET-002 — PowerShell Encoded Command (VALIDATED)

| Suggested file | Source | Shows | Story fit | Status |
|---|---|---|---|---|
| `evidence/det002-rule100005-encoded.png` | `Screenshot_20260927_031425.png` | windows-victim event: custom rule 100005 `Detection Platform: PowerShell with encoded command [T1059.001]`, level 10, at 03:13 — first custom Sysmon rule firing in the lab | SIEM view | Present |
| Still to capture: `evidence/det002-encoded-attack.png` | — | The `powershell -enc …` run on windows-victim that produced it | Attack view — missing |

## DET-003 — PowerShell Download Cradle (VALIDATED)

| Suggested file | Source | Shows | Story fit | Status |
|---|---|---|---|---|
| `evidence/det003-rule100004-alert.png` | `Screenshot_20260927_185353.png` | Threat Hunting, `rule.id:100004`, 1 hit on windows-victim: `Detection Platform: PowerShell download cradle - fetch and execute pattern [T1059.001]`, level 10, 2026-09-27 18:51:56 | SIEM view | Present |
| Still to capture: `evidence/det003-cradle-attack.png` | — | The `DownloadString`+`IEX` cradle run on windows-victim that produced it | Attack view — missing |

## DET-004 — LSASS Credential Dumping via comsvcs MiniDump (validated per campaign log, no firing screenshot)

None of the three files below is in the repo, so there is no screenshot of
custom rule 100003 firing. The firing is recorded in the campaign log only.

| Suggested file | Source | Shows | Story fit | Status |
|---|---|---|---|---|
| `evidence/det004-lsass-92900-svchost.png` | `Screenshot_20260927_015031.png` | Threat Hunting filtered on `data.win.eventdata.targetImage:*lsass*` (2 hits): rule 92900 `Lsass process was accessed by C:\Windows\system32\svchost.exe with read permissions, possible credential dump`, level 12 | SIEM view — doubles as the FP case in `det-004`: stock 92900 fires on benign svchost read access, which is why custom rule 100003 keys on sensitive masks | Not captured (file not in repo) |
| Still to capture: `evidence/det004-comsvcs-attack.png` | — | ART T1003.001 `rundll32.exe comsvcs.dll, MiniDump` run on windows-victim | Attack view — missing |
| Still to capture: `evidence/det004-rule100003-alert.png` | — | Custom rule 100003 firing (×2 per campaign log) with GrantedAccess mask visible | SIEM view — not yet captured; neither Screenshots folder contains a shot of `rule.id:100003` firing despite the det-doc/campaign-log recording it fired twice — capture on next lab session |

## DET-005 — New Local User Creation (validated via stock rules 60109/60110 and EID 4722)

None of these files is in the repo. The alerts described are stock rules;
custom rule 100002 firing is not evidenced.

| Suggested file | Source | Shows | Story fit | Status |
|---|---|---|---|---|
| `evidence/det005-net-user-backdoor.png` | `Screenshot_20260927_005426.png` | Admin PowerShell: `net user backdoor P@ssw0rd123 /add` → `The command completed successfully.` | Attack view | Not captured (file not in repo) |
| `evidence/det005-user-created-alerts.png` | `Screenshot_20260927_005437.png` | windows-victim events: 60109 `User account enabled or created`, 60110 `User account changed`, plus 92039 net.exe / 92033 PowerShell discovery hits | SIEM view | Not captured (file not in repo) |
| `evidence/det005-eid4722-drilldown.png` | `Screenshot_20260927_005642.png` | Document Details drill-down: EID 4722 `A user account was enabled`, Target `backdoor`, Subject: the local operator account on the Windows victim | SIEM view — field-level proof for the writeup | Not captured (file not in repo) |

## DET-006 — Scheduled Task Creation (VALIDATED)

| Suggested file | Source | Shows | Story fit | Status |
|---|---|---|---|---|
| `evidence/det006-rule100006-task.png` | `Screenshot_20260927_031700.png` | windows-victim event: custom rule 100006 `Detection Platform: Scheduled task created (4698) [T1053.005]`, level 7, at 03:16 — plus `Wazuh server started` (rule deploy restart) right above it | SIEM view | Present |
| `evidence/det006-scheduled-task-60228.png` | `Screenshot_20260927_015819.png` | windows-victim events: stock `A scheduled task was created` (rule 60228) at 01:57 — the parent event custom 100006 chains off | SIEM view — supporting | Not captured (file not in repo) |
| Still to capture: `evidence/det006-schtasks-attack.png` | — | `schtasks /create /tn LabTest …` run on windows-victim | Attack view — missing |

## DET-007 — Suspicious Service Creation (VALIDATED)

| Suggested file | Source | Shows | Story fit | Status |
|---|---|---|---|---|
| `evidence/det007-rule100011-alert.png` | `Screenshot_20260927_184422.png` | Threat Hunting, `rule.id:100011`, 1 hit on windows-victim: `Detection Platform: Service created with suspicious binary path [T1543.003]`, level 10, 2026-09-27 18:43:53 | SIEM view | Present |
| Still to capture: `evidence/det007-sc-create-attack.png` | — | ART T1543.003 run with `binary_path=C:\Temp\AtomicService.exe` (`-PromptForInputArgs`) on windows-victim | Attack view — missing |

## DET-011 — Clearing Windows Security Event Log (VALIDATED)

| Suggested file | Source | Shows | Story fit | Status |
|---|---|---|---|---|
| `evidence/det011-wevtutil-attack.png` | `Screenshot_20260927_182528.png` | Admin PowerShell on windows-victim: Atomic Red Team test **T1685.005-4 "BlackCat Ransomware Full Log Clear"** looping `wevtutil.exe cl "<log>"` across dozens of event-log channels (including Security), ending `Failed to clear log Microsoft-Windows-LiveId/Analytic ... Access is denied. Exit code: -1. Done executing test: T1685.005-4 BlackCat Ransomware Full Log Clear` | Attack view — confirms this ran as an ART atomic test, not a bare manual `wevtutil cl Security` | Present |
| `evidence/det011-rule100007-alert.png` | `DET-011.png` | Threat Hunting, `rule.id:100007`, 1 hit on windows-victim: `Detection Platform: Windows Security event log cleared (1102) [T1685.005]`, level 10, 2026-09-27 18:22:44 — fired after the `if_sid 63103` parent fix | SIEM view | Present |

## Module 4 — SOAR triage pipeline

Status reflects what is actually in `shared/evidence/`.

| Suggested file | Status | Shows |
|---|---|---|
| `evidence/telegram-alert-triage.png` | Present | Telegram alert for rule 100005 (level 10, windows-victim) with AI triage sections |
| `evidence/telegram-alert-triage-92213.png` | Present | Telegram alert for built-in rule 92213 (level 15, windows-victim), a second detection from the same host |
| `evidence/n8n-workflow-canvas.png` | Present | The 9-node SOC Alert Triage workflow on the n8n canvas |
| `evidence/n8n-execution-success.png` | Present | A successful execution record, one run, end to end |

## Supporting (no DET yet)

| Suggested file | Source | Shows | Story fit | Status |
|---|---|---|---|---|
| `evidence/supporting-executable-drop-92217.png` | `Screenshot_20260927_010020.png` | Burst of rule 92217 `Executable dropped in Windows root folder` on windows-victim (00:58:35) | Attack-story context (payload drops); candidate for a future file-creation DET or DET-007 dropper analysis | Not captured (file not in repo) |

## Still to capture (no screenshots yet)

Planned captures not covered by the tables above. Entries marked "Not
captured" earlier in this file also still need doing.

| Suggested file | DET | What to grab (attack + SIEM) |
|---|---|---|
| `evidence/det002-encoded-attack.png` | DET-002 | `powershell -enc …` run (SIEM side is present, rule 100005 firing) |
| `evidence/det003-cradle-attack.png` | DET-003 | DownloadString+IEX cradle run on windows-victim (SIEM side is present, rule 100004 firing) |
| `evidence/det004-comsvcs-attack.png` / `evidence/det004-rule100003-alert.png` | DET-004 | ART T1003.001 `rundll32 comsvcs.dll, MiniDump` run + custom rule 100003 firing. Neither view is captured, and the stock-92900 shot is also missing |
| `evidence/det013-*` | DET-013 | Attack run (ART T1547.001) and the alert for rule 100021 (DET-013), once the run is recorded. See `attack-tests/t1547-001-registry-run-key.md` |
| `evidence/det006-schtasks-attack.png` | DET-006 | `schtasks /create /tn LabTest …` run on windows-victim |
| `evidence/det007-sc-create-attack.png` | DET-007 | ART T1543.003 run with overridden `binary_path` on windows-victim (SIEM side is present, rule 100011 firing) |
| `evidence/det008-chmod-suid-attack.png` / `evidence/det008-auditd-execve.png` | DET-008 | `chmod u+s /tmp/lab_suid` + auditd EXECVE record — blocked on L-001 (auditd dead on linux-victim, needs reboot) |
| `evidence/det009-revshell-attack.png` / `evidence/det009-auditd-execve.png` | DET-009 | Loopback `bash -i >& /dev/tcp/…` + EXECVE telemetry (loopback only) — blocked on L-001 |
| `evidence/det010-hydra-then-login.png` / `evidence/det010-correlation.png` | DET-010 | Hydra burst + one good login from same IP, then the temporal correlation firing |

## Reviewed and not filed

Some screenshots in the source folders were reviewed and are not evidence for
any detection (earlier lab builds with superseded rules, and unrelated
personal images). They are excluded from this repository on purpose.

## Conventions

- `detNNN-<what>.png` — detection evidence, numbered by Detection ID.
- `lab-*` / `siem-*` — environment and overview shots.
- `supporting-*` — useful context not tied to a DET (yet).
- When a DET flips to TESTED/VALIDATED, update its Status in the
  corresponding `docs/detections/det-*.md` and keep filenames stable so
  writeups don't rot.
- Do not mark a DET VALIDATED on the strength of a stock Wazuh rule alone
  without saying so (DET-001, DET-005), and do not index a filename as
  captured until the file is in `shared/evidence/`.
