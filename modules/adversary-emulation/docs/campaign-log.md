# Campaign Log — Workstream 1 (Windows Campaign)

Chronological log of the Adversary Emulation module's Workstream 1
close-out: standing up Atomic Red Team on `windows-victim` and running it
through the Windows-side custom Wazuh rules that were sitting UNTESTED in
the [Detection Pipeline attack matrix](../../detection-pipeline/docs/attack-matrix.md).
Per-technique detail lives in `../attack-tests/`; this log is the
narrative — what was tried, what broke, in what order.

## Pre-campaign: manual validations (2026-09-26 → early 2026-09-27)

Before ART was installed, five detections were already validated with
hand-run commands (no attack framework needed for these):

- DET-001 (SSH brute force) — `hydra` burst from the Parrot attacker box.
- DET-002 (PowerShell encoded command) — `powershell -enc ...`.
- DET-005 (local user creation) — `net user backdoor /add`.
- DET-006 (scheduled task creation) — `schtasks /create`.
- DET-012 (notepad canary) — pipeline proof, `notepad.exe`.

This left DET-003, DET-004, DET-007 and DET-011 UNTESTED — the techniques
that needed either a heavier attack tool (LSASS dumping) or were simply
next in the queue. Decided to bring in Atomic Red Team for this batch
rather than keep hand-rolling commands, both for realism and to build
reusable F2 tooling.

## The ART install saga

Installing Atomic Red Team on `windows-victim` was not a one-command
affair:

1. **Disk space.** The Win10 victim VM's system disk was tight; the
   initial `Install-AtomicRedTeam` attempt failed partway through
   downloading the atomics content. Freed up space before retrying.
2. **Execution policy.** PowerShell's default execution policy blocked
   the installer script from running unsigned. Had to relax it
   (`Set-ExecutionPolicy` scoped to the session/process) to let the
   installer run at all — expected friction on a hardened-by-default
   Win10 image, but cost time to diagnose since the failure mode
   (silent script refusal) wasn't an obvious error message at first.
3. **Installer script vs. module.** Initial attempts tried invoking
   Atomic Red Team as if it were already an installed PowerShell module
   (`Import-Module` before it existed / mixing up the bootstrap
   installer script with the `Invoke-AtomicRedTeam` module it installs).
   Sorted out the correct sequence: run the install script first
   (installs the module + downloads the atomics content), *then*
   `Import-Module` and call `Invoke-AtomicTest`.

Once installed cleanly, the actual technique tests were comparatively
quick.

## Technique tests (2026-09-27)

Ran in this order; full command-level detail is in `../attack-tests/`:

1. **T1003.001 — LSASS dump (comsvcs.dll MiniDump).** First ART-driven
   test post-install. `rundll32.exe comsvcs.dll, MiniDump` against the
   LSASS PID. Sysmon EID 10 shipped, custom rule 100003 fired — twice
   (rundll32 opens the LSASS handle across two distinct access events for
   this technique). DET-004 → VALIDATED.
2. **T1059.001 — PowerShell download cradle.** `DownloadString` + `IEX`
   against a benign payload served from the attacker box. Custom rule
   100004 fired clean, no surprises. DET-003 → VALIDATED.
3. **T1053.005 — Scheduled task.** Already validated pre-campaign
   (manual `schtasks`); not re-run under ART.
4. **T1685.005 — Clear Windows Security log.** Ran ART test T1685.005-4
   "BlackCat Ransomware Full Log Clear" (loops `wevtutil cl` across dozens
   of channels including Security). This is where things got interesting
   — see "Bugs found" below. Once both bugs were fixed, custom rule 100007
   fired at 18:22:44. DET-011 → VALIDATED.
5. **T1543.003 — Suspicious service creation.** Ran ART's default test
   first (`binary_path` under `C:\AtomicRedTeam\...`) — EID 7045 shipped
   but rule 100011 correctly did *not* fire, since the rule's pattern
   list is threat-model-based (real attacker staging paths) and has no
   reason to match ART's own install directory. Re-ran with
   `-PromptForInputArgs`, set `binary_path=C:\Temp\AtomicService.exe`,
   and rule 100011 fired as expected. DET-007 → VALIDATED. Notable
   lesson: a rule *not* firing on the naive test run was the correct
   behavior, not a bug — worth documenting the negative result rather
   than just re-running until it fires.

## Bugs found

### 1. Rule-parenting assumption #1 — DET-011 (100007)

Rule 100007 was authored anchored on
`<if_group>windows_security</if_group>` on the (reasonable-looking but
wrong) assumption that any Security-channel event would chain off that
group. In fact EventID 1102 decodes under the specific stock parent rule
**63103**, not the generic group. The rule silently never fired — no
error, just no alerts, which took longer to notice than a hard failure
would have. Fixed to `<if_sid>63103</if_sid>`, verified with
`wazuh-logtest` before redeploying. Full detail:
`../../detection-pipeline/docs/detections/det-011-security-log-cleared.md`.

### 2. Rule-parenting assumption #2 — same family as #1

Same class of mistake as above: assuming a plausible-but-generic parent
(a channel-wide group) instead of verifying the actual decoded parent
rule for the specific EventID. Both were caught by the same
`wazuh-logtest`-first discipline adopted after the first one — now
standard practice before any parent-anchored rule change (see
`shared/lessons-learned.md`).

### 3. CD hot-reload bug

After fixing rule 100007's parent and pushing, the deploy workflow
reported success (HTTP 200, `"error": 0` from the Wazuh API PUT) but the
rule still didn't fire on re-test. The API PUT writes `local_rules.xml`
to disk correctly, but `analysisd` in this single-node docker deployment
does not hot-reload rule files from a PUT alone — it needs a manager
restart. `deploy-wazuh.yml` was fixed to restart
`single-node-wazuh.manager-1` and verify agent connectivity as an
explicit step after every deploy. This bug affects *every* rule
edit/deploy, not just this one — it was simply found here first because
this was the first mid-campaign rule fix that needed a redeploy.

## The in-memory cradle lesson

Validating the PowerShell download cradle (T1059.001, DET-003) reinforced
a detection-engineering point worth keeping: the cradle
(`DownloadString`+`IEX`) never writes the payload to disk — it fetches
and executes in a single in-memory step. Sysmon EID 1's `CommandLine`
field is the *only* place the full cradle is visible; there's no
file-creation or file-write event to fall back on if process-creation
logging is ever disabled or tampered with for this specific technique.
This is a real detection boundary (not a bug) worth calling out
explicitly rather than assuming "we'll catch it somewhere else in the
pipeline" — see `shared/lessons-learned.md`.

## Outcome

7 techniques covered in this writeup (T1110.001, T1136.001, T1003.001,
T1059.001, T1053.005, T1685.005, T1543.003), 4 flipped from UNTESTED to
VALIDATED this session (DET-003, DET-004, DET-007, DET-011), bringing the
Detection Pipeline matrix to 9/12 at the time (12 detections then; DET-013 was added later, making it 9/13). DET-008/DET-009 (Linux/auditd) remain
untested, blocked upstream by the auditd ingestion gap — not an ART or
campaign issue, see
`../../detection-pipeline/docs/known-limitations.md` L-001.
