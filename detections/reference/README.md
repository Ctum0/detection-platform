# Reference detections (not deployed)

This directory contains Sigma detection specifications that serve as reference implementations or syntax examples, but are not deployed to Wazuh or converted to Splunk SPL.

## Files

- `ssh_success_after_failures.yml` (formerly DET-010): Demonstrates Sigma's `temporal_ordered` correlation rule syntax across multiple authentication events.
  - **Why not deployed:** Wazuh's analysis engine does not support `temporal_ordered` correlation semantics across events (only simple frequency/timeframe counts via `event_count` are supported, as used in `ssh_bruteforce.yml`). Additionally, `temporal_ordered` is not supported by the pySigma Splunk backend.
  - **Status:** Retained as an authoring reference for advanced Sigma correlation syntax.
