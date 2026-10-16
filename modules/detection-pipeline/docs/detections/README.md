# Detections docs

One markdown file per detection (`det-NNN-<slug>.md`), following the DET-001
template: header table (Detection ID, Rule with Sigma + Wazuh ID + SPL,
Data source, ATT&CK, Severity, Status) then Logic, Expected telemetry,
Validation method, FP notes, Investigation guidance. Statuses mirror
`../attack-matrix.md` (VALIDATED only with attack + alert evidence indexed
in `../../../../shared/evidence-index.md`).

DET-013 is PENDING (merged, not deployed, not validated).
