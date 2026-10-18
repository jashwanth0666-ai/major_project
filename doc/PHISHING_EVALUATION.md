# Frozen URL model evaluation

The enterprise evaluation script described by earlier project reports is not
present in this checkout. The checked-in Phase 4 calibrated artifact remains
available for runtime and bounded batch inference through
`api/inference/detector.py`. The detector does not train, calibrate, tune, or
modify the model.

From the repository root in PowerShell:

```powershell
.\.venv\Scripts\python.exe -m api.inference.detector --batch .\INPUT.csv --output .\ml_model\phase5\predictions.csv
```

For a quick deterministic diagnostic, add `--sample-size 1000`. This is stratified by label with seed 42 and must not be reported as a full-split result. `--threshold` supports sensitivity analysis only; the selected value and override are recorded, and the risk-engine configuration is never changed.

## Outputs

Artifacts are written to the ignored local directory `ml_model/phase5/enterprise_evaluation/`:

- `evaluation_report.md` and `evaluation_summary.json`: model hash, threshold provenance, full split metrics, row-level Wilson intervals, calibration error, and temporal-evaluation state.
- `predictions_*.csv`: one scored row per evaluated URL, with credentials, query strings, fragments, and sensitive/opaque path segments removed from the review URL. A SHA-256 of the original URL supports local joining.
- `domain_review_*.csv`: per-domain counts and error rates for domains with at least 20 rows, to identify clusters requiring label review.
- `label_review_queue_*.csv`: bounded false-positive and false-negative queues with blank reviewer adjudication fields. The script does not assume labels have been reviewed or move reviewed rows into training.
- `source_label_counts_*.csv`: label distribution by source when the split includes that metadata.

Precision, recall, and FPR intervals use Wilson binomial intervals over rows; they do not model within-domain correlation. Per-domain summaries provide additional context. The split overlap audit is copied into the JSON report when available.

## Temporal limitation

The current data documentation states that the master dataset has no reliable timestamps. The evaluator therefore reports temporal validation as unavailable and does not invent collection dates from source names or file metadata. Before a time-based holdout is added, each observation needs a documented first-seen or collection timestamp, timezone, source provenance, and label-time semantics. Domain and time boundaries must be frozen before threshold selection, and reviewed labels must retain reviewer and evidence provenance.

This workflow evaluates the existing frozen model only. A model or threshold change still needs a separate reviewed benchmark, time/domain-separated validation, calibration assessment, staged artifact release, and rollback plan.
