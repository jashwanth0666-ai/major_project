"""
Phase 3 - False-Positive Evaluation and Multi-Signal Validation (planned, not executed).

This script is a reproducible evaluation scaffold. It does NOT run the model or
fabricate metrics. It documents the intended workflow and can be executed later
in a disposable environment with an approved labeled dataset.

Inputs:
  --input CSV with columns: url,label  (label in {0,1} or benign/phishing)
  --output directory for reports

It compares:
  - Baseline: existing calibrated ML probability + threshold 0.15
  - Experimental: fused_risk_score (heuristic) converted to a binary decision
    using an explicitly documented experimental threshold (NOT 0.15).

No production model, calibration, threshold, policy, or blocking behavior is
changed by this script.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
from pathlib import Path
from urllib.parse import urlparse

import numpy as np

# Reuse existing inference without retraining.
from phase5_inference import WatchDogDetector, extract_features, THRESHOLD


def domain_of(url: str) -> str:
    try:
        host = (urlparse(url).hostname or "").lower()
    except Exception:
        return ""
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def split_by_domain(rows, test_ratio=0.3, seed=42):
    """Group-aware split to reduce leakage. Returns (train, test) row lists."""
    rng = np.random.default_rng(seed)
    domains = sorted({domain_of(r["url"]) for r in rows})
    rng.shuffle(domains)
    cutoff = int(len(domains) * (1 - test_ratio))
    train_domains = set(domains[:cutoff])
    train = [r for r in rows if domain_of(r["url"]) in train_domains]
    test = [r for r in rows if domain_of(r["url"]) not in train_domains]
    return train, test


def validate_dataset(rows):
    """Dataset integrity checks (planned; not executed here). Returns list of issues."""
    issues = []
    if not rows:
        issues.append("Empty dataset.")
        return issues
    required = {"url", "label"}
    if not required.issubset(rows[0].keys()):
        issues.append(f"Missing required columns: {required - set(rows[0].keys())}")
        return issues
    seen = {}
    for i, r in enumerate(rows):
        url = (r.get("url") or "").strip()
        label = r.get("label")
        if not url:
            issues.append(f"Row {i}: missing URL.")
        if label is None or str(label).strip() == "":
            issues.append(f"Row {i}: missing label.")
        # duplicate / conflicting labels
        if url in seen and seen[url] != str(label).strip().lower():
            issues.append(f"Row {i}: conflicting label for duplicate URL {url!r}.")
        seen[url] = str(label).strip().lower() if label is not None else ""
    # domain grouping note is documentation, not an issue.
    return issues
    s = str(label).strip().lower()
    if s in {"1", "phishing", "malicious", "true", "yes"}:
        return 1
    return 0


def to_binary(label) -> int:
    s = str(label).strip().lower()
    if s in {"1", "phishing", "malicious", "true", "yes"}:
        return 1
    if s in {"0", "benign", "legitimate", "false", "no"}:
        return 0
    raise ValueError(f"Unrecognized label: {label!r}")


def evaluate(rows, detector):
    y_true = []
    y_base = []   # baseline ML decision at 0.15
    y_exp = []    # experimental fused decision (threshold documented below)
    details = []
    for r in rows:
        url = r["url"]
        label = to_binary(r["label"])
        try:
            res = detector.predict(url)
        except Exception as exc:
            details.append({"url": url, "label": label, "domain": domain_of(url), "error": str(exc)})
            continue
        prob = res["phishing_probability"]
        base_decision = 1 if prob >= THRESHOLD else 0
        fused = res["experimental"]["fused_risk_score"]
        # Experimental threshold is arbitrary and documented; not production.
        exp_decision = 1 if fused >= 50 else 0
        y_true.append(label)
        y_base.append(base_decision)
        y_exp.append(exp_decision)
        details.append({
            "url": url,
            "label": label,
            "domain": domain_of(url),
            "ml_probability": prob,
            "baseline_decision": base_decision,
            "fused_risk_score": fused,
            "experimental_decision": exp_decision,
            "signals": res["signals"],
        })
    return y_true, y_base, y_exp, details


def metrics(y_true, y_pred):
    tp = sum(1 for a, b in zip(y_true, y_pred) if a == 1 and b == 1)
    tn = sum(1 for a, b in zip(y_true, y_pred) if a == 0 and b == 0)
    fp = sum(1 for a, b in zip(y_true, y_pred) if a == 0 and b == 1)
    fn = sum(1 for a, b in zip(y_true, y_pred) if a == 1 and b == 0)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return {
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "f1": round(f1, 6),
        "false_positive_rate": round(fpr, 6),
    }


def disagreement_analysis(details):
    out = []
    for d in details:
        if d["baseline_decision"] != d["experimental_decision"]:
            out.append({
                "url": d["url"],
                "label": d["label"],
                "ml_probability": d["ml_probability"],
                "fused_risk_score": d["fused_risk_score"],
                "baseline": d["baseline_decision"],
                "experimental": d["experimental_decision"],
            })
    return out


def main():
    parser = argparse.ArgumentParser(description="Phase 3 false-positive evaluation (planned).")
    parser.add_argument("--input", type=Path, required=True, help="Labeled CSV with url,label columns.")
    parser.add_argument("--output", type=Path, default=Path("data/phase3_eval"), help="Output directory.")
    parser.add_argument("--model", type=Path, default=None, help="Model artifact path.")
    parser.add_argument("--test-ratio", type=float, default=0.3)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    rows = []
    with open(args.input, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            if "url" in r and "label" in r:
                rows.append(r)

    issues = validate_dataset(rows)
    report["dataset_issues"] = issues

    train, test = split_by_domain(rows, args.test_ratio, args.seed)

    detector = WatchDogDetector(args.model) if args.model else WatchDogDetector()

    y_true, y_base, y_exp, details = evaluate(test, detector)

    report = {
        "dataset": str(args.input),
        "random_seed": args.seed,
        "test_ratio": args.test_ratio,
        "split_strategy": "group-by-domain (last two labels), shuffled with seed",
        "baseline_threshold": THRESHOLD,
        "experimental_threshold": 50,
        "experimental_threshold_note": "Arbitrary; not the production 0.15 threshold.",
        "total_rows": len(rows),
        "train_rows": len(train),
        "test_rows": len(test),
        "threshold_baseline": THRESHOLD,
        "threshold_experimental": 50,
        "baseline_metrics": metrics(y_true, y_base),
        "experimental_metrics": metrics(y_true, y_exp),
        "disagreements": disagreement_analysis(details),
        "note": "Experimental metrics use an arbitrary fused-score threshold; not production. No model retrained.",
    }

    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    if details:
        with open(args.output / "details.csv", "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(details[0].keys()))
            writer.writeheader()
            for d in details:
                writer.writerow({k: (json.dumps(v) if isinstance(v, (dict, list)) else v) for k, v in d.items()})
    else:
        (args.output / "details.csv").write_text("", encoding="utf-8")

    print(f"Wrote {args.output / 'report.json'} and details.csv (not executed here).")


if __name__ == "__main__":
    main()
EOF
# place in scripts
Move-Item -Path "phase3_false_positive_eval.py" -Destination "scripts\phase3_false_positive_eval.py" -Force 2>$null
Write-Host done