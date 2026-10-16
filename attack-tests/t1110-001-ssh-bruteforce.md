# T1110.001 — SSH Brute Force (Password Guessing)

Validates: [DET-001](../modules/detection-pipeline/docs/detections/det-001-ssh-bruteforce.md)
(Wazuh stock 5712, custom 100008/100009)

## Commands

Run from the Parrot attacker box against `linux-victim`:

```bash
hydra -l nonexistentuser -P rockyou.txt -t 4 <victim-ip> ssh
```

## Expected telemetry

sshd `Failed password for ...` lines streamed via `/var/log/auth.log`,
aggregated by source IP.

## Rules fired

- Stock 5710 `sshd: Attempt to login using a non-existent user` (streamed
  throughout the burst).
- Stock 5712 `sshd: brute force trying to get access to the system. Non
  existent user.` at 76 tries/min.
- Custom 100008 (base failed-auth) and 100009 (frequency 6/600s
  correlation) fire on the same telemetry, since the Sigma rule covers
  the same condition as the stock correlation.

## Cleanup

None required — no state changes on the victim; `nonexistentuser` never
existed.

## Notes

Earliest validated technique in the lab (2026-09-26), predates the
Atomic Red Team install — run as a raw `hydra` command, not an ART test.
The alert was stock rule 5712; custom 100008/100009 were not shown
firing. Planned screenshots (`shared/evidence/det001-*.png`) are not in
the repo; see `shared/evidence-index.md`.
