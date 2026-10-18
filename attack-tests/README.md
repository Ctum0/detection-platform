# Attack tests

One scenario writeup per validated technique. Each maps to a detection in
the [Detection Pipeline](../modules/detection-pipeline/README.md) module:

- `attack-tests/<technique>.md` — exact commands (ART invocation and/or
  manual commands), expected telemetry, rules fired, cleanup, notes.
- Links the detection doc in `../modules/detection-pipeline/docs/detections/`
  and the rule in `../detections/`.

Chronological narrative of the campaign that produced these lives in
`../modules/adversary-emulation/docs/campaign-log.md`.

All 10 deployable detections have completed validations recorded with
evidence in `shared/evidence-index.md` (including `t1547-001-registry-run-key.md` / DET-013).
