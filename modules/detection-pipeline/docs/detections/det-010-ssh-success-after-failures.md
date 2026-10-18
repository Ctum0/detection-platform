# DET-010 — SSH Successful Login After Multiple Failures

| Field | Value |
|---|---|
| Detection ID | DET-010 |
| Rule | Sigma `detections/reference/ssh_success_after_failures.yml` (3-doc file: 2 base rules + `temporal_ordered` correlation); Wazuh: not deployed (`temporal_ordered` unsupported); no SPL |
| Data source | `/var/log/auth.log` (sshd) via Wazuh agent |
| ATT&CK | T1110.001 — Password Guessing |
| Severity | High |
| Status | REFERENCE — not deployed (syntax reference for Sigma temporal_ordered correlations) |

## Logic

`ssh_failed_auth_event` (sshd `Failed password`) ordered-before `ssh_success_auth_event` (sshd `Accepted password/publickey`), grouped by `src_ip` within 15 minutes. Builds on the DET-001 brute-force base telemetry; this rule answers "did they get in?".

## Expected telemetry

A burst of `Failed password for ... from <src_ip>` lines followed by `Accepted ... for ... from <src_ip>` from the same source within the window. Requires `src_ip` parsed (Wazuh sshd decoder); otherwise tune the `group-by` field.

## Validation method

1. Run a small hydra burst against a lab account with a wrong-password list, then log in correctly once from the same attacker IP.
2. Confirm the correlation fires and names the source IP and account.

## FP notes

A user failing repeatedly then remembering the password triggers this — check attempt count, timing and account context before escalating.

## Investigation guidance

1. Compromised account? Force password rotation and review its post-login activity.
2. Source IP reputation; block at perimeter if hostile.
3. Timeline: first failure → success; any lateral movement after?
