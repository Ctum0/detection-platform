# Pipeline Demo — End-to-End Detection Delivery

This folder documents the complete detection-as-code lifecycle, proven live
in the lab: a detection is written as Sigma, validated by CI, deployed
to Wazuh automatically via CD, and proven by executing the attack it
detects. Screenshots in this folder (named `NN-description.png`) are the
evidence for each step.

## The full loop

```
 Analyst writes Sigma rule (detections/sigma/*.yml)
        |
        v  git push
 GitHub Actions CI (.github/workflows/validate.yml)
        |  - sigma check: schema + syntax + ATT&CK tag validation
        |  - sigma convert: auto-generates Splunk SPL
        |  - generated .spl files committed back to repo
        v
 GitHub Actions CD (.github/workflows/deploy-wazuh.yml)
        |  - runs on self-hosted runner (VPS)
        |  - uploads custom_rules.xml via Wazuh API
        |  - restarts the manager (single-node docker does not hot-reload
        |    rule files on PUT alone — see shared/lessons-learned.md)
        |  - verifies HTTP 200 + error 0, then that the rule IDs are reported back
        v
 Wazuh Manager (rules live)
        |
        v  attack executed on victim
 Alert fires with custom rule ID
        |
        v
 Threat Hunting / investigation / documentation
```

Note: this diagram is the loop as it was when the demo was run. The
`convert-deploy.yml` step between CI and CD was added later; at demo time
rule 100012 was written into `custom_rules.xml` by hand.

## Live test walkthrough (DET-012, rule 100012)

The test detection: **Notepad execution** — trivial by design, so the
pipeline itself is what's being tested, not the detection logic.

| Step | What happens | Evidence |
|---|---|---|
| 1. Rule written | `detections/sigma/notepad_execution.yml` created; rule 100012 added to `custom_rules.xml`; `sigma check` = 0 errors, `wazuh-analysisd -t` precheck clean | `01-sigma-rule.png` |
| 2. Push triggers CI | validate.yml runs: sigma check passes, SPL auto-generated and committed | `02-ci-validate-green.png` |
| 3. Push triggers CD | deploy-wazuh.yml runs on the VPS runner: XML uploaded via API, HTTP 200, verify step greens | `03-deploy-green.png` (same Actions page as step 2; `Deployed OK` line is in the run logs) |
| 4. Attack executed | `notepad.exe` run on win-victim; Sysmon Event ID 1 generated | `04-notepad-attack.png` |
| 5. Custom rule fires | Alert `100012 — Detection Platform: Notepad execution` appears in Threat Hunting | `05-alert-100012.png` |

Total elapsed time from `git push` to alert: under 2 minutes.

## Debugging war story (why this demo matters)

The first deploy "succeeded" but deployed nothing — a lesson in CI
false-positives:

1. **Silent failure:** the deploy step used `curl -s` without checking the
   status, which swallows HTTP errors and exits 0. The workflow showed
   green while the manager still ran old rules. Fixed by capturing the HTTP code and failing loudly on
   anything but 200 + `"error": 0`.
2. **Wazuh API bug:** XML comments containing HTML-escaped entities
   (`&gt;`, `&amp;`) crash the 4.14 API's rule-upload parser with a
   500/PicklingError. Fixed by keeping the deployed XML comment-free
   (mapping lives in `detections/wazuh/DEPLOY-NOTES.md`).
3. **Duplicate rule IDs:** a `local_rules.xml.bak-*` file left inside the
   rules directory was loaded by analysisd alongside the live file,
   double-defining every custom rule ("only first occurrence considered" —
   a coin-flip on which version won). Fixed by moving backups out of the
   rules directory; clean boot now loads all rules with zero warnings.
4. **Telemetry stall vs. idle hosts:** during testing, Sysmon events
   appeared to stop flowing. Root cause was benign: victim VMs idle at
   ~4:45 AM generated nothing to send, and the benign Notepad test matched
   only a level-0 rule (correctly not indexed as an alert). Combined with
   the backup-file duplicate issue, this looked like a frozen pipeline.
5. **API PUT doesn't hot-reload (found later, W1 close-out):** the API PUT
   returns HTTP 200 and the file is written to disk, but `analysisd` in
   this single-node docker deployment does not pick up rule changes from a
   PUT alone — a manager restart is required before a newly deployed or
   edited rule actually fires. Found while debugging why the DET-011
   parent fix (100007) wasn't taking effect after a clean 200 deploy.
   `deploy-wazuh.yml` now restarts the manager container as a dedicated
   step after every deploy. See `shared/lessons-learned.md`.

Each issue is documented because debugging the pipeline is as much a
detection-engineering skill as writing the rules.

## Custom rules validated live (as of this demo)

Single source of truth for validation status is `docs/attack-matrix.md`
(currently 9/13 validated). Custom rules proven firing by their own alerts:

| Rule | Detection | Technique | Proven by |
|---|---|---|---|
| 100002 | Local user creation (4720) | T1136.001 | `net user backdoor /add` |
| 100003 | LSASS access (comsvcs MiniDump) | T1003.001 | ART T1003.001, `rundll32 comsvcs.dll MiniDump` |
| 100004 | PowerShell download cradle | T1059.001 | ART-style `DownloadString`+`IEX` cradle |
| 100005 | Encoded PowerShell | T1059.001 | `powershell -enc ...` |
| 100006 | Scheduled task creation (4698) | T1053.005 | `schtasks /create` |
| 100007 | Security log cleared (1102) | T1685.005 | `wevtutil cl Security` |
| 100011 | Suspicious service creation (7045) | T1543.003 | `sc create` with binary_path under `C:\Temp\` |
| 100012 | Notepad execution (canary) | T1098 | `notepad.exe` (this demo) |

Stock-rule observations (useful context, not custom-rule proof): 5712 fired
on the hydra burst (DET-001), 92900 fired on benign svchost LSASS access
(the FP case behind DET-004), 60228 observed for task creation (parent of
100006). Custom rules 100001, 100008/100009 and 100010 remain UNTESTED —
see `docs/attack-matrix.md` and `docs/known-limitations.md`.
