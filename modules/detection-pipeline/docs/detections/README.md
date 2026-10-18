# Detections docs

One markdown file per detection (`det-NNN-<slug>.md`), following the DET-001
template: header table (Detection ID, Rule with Sigma + Wazuh ID + SPL,
Data source, ATT&CK, Severity, Status) then Logic, Expected telemetry,
Validation method, FP notes, Investigation guidance. Statuses mirror
`../attack-matrix.md` (VALIDATED only with attack + alert evidence indexed
in `../../../../shared/evidence-index.md`).

All 10 deployable detections are VALIDATED with evidence indexed
in `../../../../shared/evidence-index.md`. DET-010 is retained as a reference detection
(not deployed). DET-008 and DET-009 were decommissioned (see L-001 in `../known-limitations.md`).
