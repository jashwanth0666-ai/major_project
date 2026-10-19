# Frozen URL model evaluation

The checked-in Phase 4 calibrated artifact can be compared across three
inference representations using `api/inference/evaluate_url_representations.py`:
the submitted full URL, the production-safe path representation (queries,
fragments, sensitive paths, and opaque path segments removed), and
scheme-plus-host only. This is evaluation only; the script does not train,
calibrate, tune, or modify the model.

From the repository root in PowerShell:

```powershell
.\.venv\Scripts\python.exe -m api.inference.evaluate_url_representations `
  --training-data .\ml_model\splits\train.csv `
  --evaluation-data .\ml_model\splits\validation.csv `
  --output .\ml_model\phase5\validation_representation.json
```

The evaluator requires hostname-disjoint training and evaluation CSVs and reports precision, recall, F1, false-positive/negative rates, Brier score, and expected calibration error for all three representations. It includes the dataset and model hashes in its JSON output. It does not emit row-level URLs. The threshold stays fixed at the production threshold (`0.31`); the script does not select a replacement threshold.

## Outputs

Use `--output PATH.json` to save a report. The validation, held-out test, and
unseen-domain splits are available under `ml_model/splits/`; do not select a
threshold using the held-out test split. Run validation and unseen-domain
comparisons first, and reserve the test split for final reporting.

## Temporal limitation

The current data documentation states that the master dataset has no reliable timestamps. The evaluator therefore reports temporal validation as unavailable and does not invent collection dates from source names or file metadata. Before a time-based holdout is added, each observation needs a documented first-seen or collection timestamp, timezone, source provenance, and label-time semantics. Domain and time boundaries must be frozen before threshold selection, and reviewed labels must retain reviewer and evidence provenance.

This workflow evaluates the existing frozen model only. A model or threshold change still needs a separate reviewed benchmark, time/domain-separated validation, calibration assessment, staged artifact release, and rollback plan.
