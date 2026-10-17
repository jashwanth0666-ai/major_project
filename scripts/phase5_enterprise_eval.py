"""Reproduce full held-out URL metrics and produce a privacy-reduced review queue.

This evaluates the frozen Phase 4 artifact. It does not train, calibrate, or tune it.
Run from the repository root with the project's Python environment:
    python scripts/phase5_enterprise_eval.py
Use --sample-size N only for a quick deterministic diagnostic; full splits are default.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    balanced_accuracy_score,
    brier_score_loss,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))
from phase5_inference import FEATURES, WatchDogDetector, extract_features, risk_level  # noqa: E402

DATA = ROOT / "data"
DEFAULT_OUTPUT = DATA / "phase5" / "enterprise_evaluation"
SPLITS = {
    "test": DATA / "splits" / "test.csv",
    "unseen_domain_test": DATA / "splits" / "unseen_domain_test.csv",
}
RISK_CONFIG = DATA / "phase4" / "risk_engine_config.json"
TIMESTAMP_NAMES = {"timestamp", "date", "datetime", "created_at", "first_seen", "collected_at", "observed_at"}
SENSITIVE_PATH = re.compile(r"(?i)(token|session|password|secret|credential|access[_-]?key|auth[_-]?code)")
OPAQUE_SEGMENT = re.compile(r"^[A-Za-z0-9_-]{32,}$")


def normalize_label(value: object) -> int:
    label = str(value).strip().lower()
    if label in {"phishing", "bad", "1", "true"}:
        return 1
    if label in {"benign", "good", "0", "false"}:
        return 0
    raise ValueError(f"Unsupported label: {value!r}")


def safe_review_url(raw: str) -> str:
    """Drop credentials, query and fragment; hide sensitive or opaque paths."""
    try:
        parsed = urlsplit(str(raw))
        host = parsed.hostname or ""
        if not host:
            return "[redacted URL]"
        path = parsed.path or "/"
        parts = [part for part in path.split("/") if part]
        if any(SENSITIVE_PATH.search(part) or OPAQUE_SEGMENT.fullmatch(part) for part in parts):
            path = "/"
        host_display = f"[{host}]" if ":" in host else host
        port = f":{parsed.port}" if parsed.port else ""
        return urlunsplit((parsed.scheme.lower(), host_display + port, path, "", ""))
    except (ValueError, TypeError):
        return "[redacted URL]"


def wilson(successes: int, trials: int, z: float = 1.959963984540054) -> tuple[float | None, float | None]:
    if trials <= 0:
        return None, None
    p = successes / trials
    den = 1 + z * z / trials
    center = (p + z * z / (2 * trials)) / den
    margin = z * math.sqrt((p * (1 - p) / trials) + (z * z / (4 * trials * trials))) / den
    return max(0.0, center - margin), min(1.0, center + margin)


def calibration_error(y: np.ndarray, p: np.ndarray, bins: int = 10) -> float:
    edges = np.linspace(0, 1, bins + 1)
    total = len(y)
    error = 0.0
    for index in range(bins):
        mask = (p >= edges[index]) & (p < edges[index + 1] if index < bins - 1 else p <= edges[index + 1])
        if mask.any():
            error += mask.sum() / total * abs(float(y[mask].mean()) - float(p[mask].mean()))
    return float(error)


def score_urls(detector: WatchDogDetector, urls: list[str], batch_size: int) -> np.ndarray:
    """Use the production feature extractor and score batches through the frozen artifact."""
    probabilities: list[np.ndarray] = []
    for start in range(0, len(urls), batch_size):
        batch = urls[start:start + batch_size]
        rows = [extract_features(url) for url in batch]
        matrix = pd.DataFrame(rows, columns=FEATURES).astype(np.float32)
        probabilities.append(detector.model.predict_proba(matrix)[:, 1])
        print(f"    scored {min(start + len(batch), len(urls)):,}/{len(urls):,}", flush=True)
    return np.concatenate(probabilities) if probabilities else np.array([], dtype=np.float64)


def split_sample(frame: pd.DataFrame, size: int, seed: int) -> pd.DataFrame:
    if size <= 0 or len(frame) <= size:
        return frame.reset_index(drop=True)
    parts = []
    for label, group in frame.groupby("label", sort=True):
        count = min(len(group), max(1, round(size * len(group) / len(frame))))
        parts.append(group.sample(n=count, random_state=seed))
    selected = pd.concat(parts, ignore_index=False)
    if len(selected) > size:
        selected = selected.sample(n=size, random_state=seed)
    return selected.sample(frac=1, random_state=seed).reset_index(drop=True)


def evaluate(name: str, path: Path, detector: WatchDogDetector, threshold: float,
             sample_size: int, seed: int, batch_size: int, review_limit: int,
             output_dir: Path) -> tuple[dict, pd.DataFrame, pd.DataFrame]:
    if not path.is_file():
        raise FileNotFoundError(f"Missing held-out dataset: {path}")
    header = pd.read_csv(path, nrows=0).columns
    required = {"url", "label", "domain"}
    if not required.issubset(header):
        raise ValueError(f"{path} must contain columns: {sorted(required)}")
    usecols = [column for column in ("url", "label", "domain", "source") if column in header]
    frame = pd.read_csv(path, usecols=usecols, low_memory=False)
    frame = frame.dropna(subset=["url", "label"]).copy()
    frame["label"] = frame["label"].map(normalize_label).astype(np.int8)
    frame["domain"] = frame["domain"].fillna("").astype(str).str.lower().str.rstrip(".")
    frame = split_sample(frame, sample_size, seed)

    y = frame["label"].to_numpy(dtype=np.int8)
    urls = frame["url"].astype(str).tolist()
    p = score_urls(detector, urls, batch_size)
    predicted = (p >= threshold).astype(np.int8)
    score = np.clip(np.rint(p * 100), 0, 100).astype(np.int16)
    levels = np.array([risk_level(int(value)) for value in score], dtype=object)
    decisions = np.select(
        [score <= 25, score <= 50, score <= 75],
        ["ALLOW", "REVIEW", "WARN"], default="BLOCK")
    tn = int(((y == 0) & (predicted == 0)).sum())
    fp = int(((y == 0) & (predicted == 1)).sum())
    fn = int(((y == 1) & (predicted == 0)).sum())
    tp = int(((y == 1) & (predicted == 1)).sum())
    precision_ci = wilson(tp, tp + fp)
    recall_ci = wilson(tp, tp + fn)
    fpr_ci = wilson(fp, fp + tn)
    metrics = {
        "dataset": name, "path": str(path.relative_to(ROOT)), "rows": len(frame),
        "benign": int((y == 0).sum()), "phishing": int((y == 1).sum()),
        "unique_domains": int(frame.loc[frame.domain.ne(""), "domain"].nunique()),
        "threshold": threshold,
        "accuracy": float(accuracy_score(y, predicted)),
        "balanced_accuracy": float(balanced_accuracy_score(y, predicted)),
        "precision": float(precision_score(y, predicted, zero_division=0)),
        "precision_95ci_low": precision_ci[0], "precision_95ci_high": precision_ci[1],
        "recall": float(recall_score(y, predicted, zero_division=0)),
        "recall_95ci_low": recall_ci[0], "recall_95ci_high": recall_ci[1],
        "f1": float(f1_score(y, predicted, zero_division=0)),
        "false_positive_rate": fp / (fp + tn) if fp + tn else None,
        "fpr_95ci_low": fpr_ci[0], "fpr_95ci_high": fpr_ci[1],
        "false_negative_rate": fn / (fn + tp) if fn + tp else None,
        "roc_auc": float(roc_auc_score(y, p)) if len(np.unique(y)) == 2 else None,
        "pr_auc": float(average_precision_score(y, p)) if len(np.unique(y)) == 2 else None,
        "brier_score": float(brier_score_loss(y, p)),
        "expected_calibration_error_10_bins": calibration_error(y, p),
        "tn": tn, "fp": fp, "fn": fn, "tp": tp,
        "temporal_evaluation": "UNAVAILABLE_NO_RELIABLE_TIMESTAMP",
        "sampling": "FULL_SPLIT" if sample_size <= 0 else f"STRATIFIED_SAMPLE_SEED_{seed}",
    }

    predictions = pd.DataFrame({
        "url_review_safe": [safe_review_url(url) for url in urls],
        "url_sha256": [hashlib.sha256(url.encode("utf-8", errors="replace")).hexdigest() for url in urls],
        "domain": frame["domain"].to_numpy(),
        "source": frame["source"].to_numpy() if "source" in frame else "",
        "actual_label": np.where(y == 1, "phishing", "benign"),
        "phishing_probability": p,
        "threshold": threshold,
        "threshold_prediction": np.where(predicted == 1, "phishing", "benign"),
        "risk_score": score,
        "risk_level": levels,
        "policy_decision": decisions,
    })
    predictions.to_csv(output_dir / f"predictions_{name}.csv", index=False)
    if "source" in frame:
        (frame.groupby(["source", "label"], dropna=False).size().rename("rows").reset_index()
         .to_csv(output_dir / f"source_label_counts_{name}.csv", index=False))

    benign_count = (y == 0).astype(np.int32)
    phishing_count = (y == 1).astype(np.int32)
    fp_flags = ((y == 0) & (predicted == 1)).astype(np.int32)
    fn_flags = ((y == 1) & (predicted == 0)).astype(np.int32)
    grouped = pd.DataFrame({"domain": frame["domain"], "benign": benign_count,
                            "phishing": phishing_count, "false_positives": fp_flags,
                            "false_negatives": fn_flags})
    per_domain = grouped[grouped.domain.ne("")].groupby("domain", as_index=False).sum()
    per_domain["false_positive_rate"] = np.divide(per_domain.false_positives, per_domain.benign,
                                                   out=np.full(len(per_domain), np.nan), where=per_domain.benign.to_numpy() > 0)
    per_domain["false_negative_rate"] = np.divide(per_domain.false_negatives, per_domain.phishing,
                                                   out=np.full(len(per_domain), np.nan), where=per_domain.phishing.to_numpy() > 0)
    review_domains = per_domain[(per_domain.benign + per_domain.phishing) >= 20]
    review_domains.sort_values(["false_positive_rate", "benign", "false_positives"],
                               ascending=[False, False, False]).head(500).to_csv(
                                   output_dir / f"domain_review_{name}.csv", index=False)

    errors = predictions.assign(
        error_type=np.select([fp_flags == 1, fn_flags == 1], ["FALSE_POSITIVE", "FALSE_NEGATIVE"], default=""))
    errors = errors[errors.error_type.ne("")].copy()
    fp_rows = errors[errors.error_type.eq("FALSE_POSITIVE")].sort_values("phishing_probability", ascending=False).head(review_limit)
    fn_rows = errors[errors.error_type.eq("FALSE_NEGATIVE")].sort_values("phishing_probability", ascending=True).head(review_limit)
    queue = pd.concat([fp_rows, fn_rows], ignore_index=True)
    queue["review_label"] = ""
    queue["reviewer"] = ""
    queue["review_notes"] = ""
    queue.to_csv(output_dir / f"label_review_queue_{name}.csv", index=False)
    return metrics, predictions, queue


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", type=Path, default=DATA / "phase4" / "xgboost_calibrated.joblib")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--sample-size", type=int, default=0,
                        help="Deterministic label-stratified rows per split; 0 evaluates all rows.")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--batch-size", type=int, default=5000)
    parser.add_argument("--review-limit", type=int, default=5000,
                        help="Maximum false positives and false negatives queued per split.")
    parser.add_argument("--threshold", type=float, default=None,
                        help="Override frozen risk_engine_config threshold for analysis only; never writes config.")
    args = parser.parse_args()
    if args.sample_size < 0 or args.batch_size < 1 or args.review_limit < 1:
        parser.error("sample-size must be >= 0; batch-size and review-limit must be positive")
    if args.threshold is not None and not 0 <= args.threshold <= 1:
        parser.error("threshold must be between 0 and 1")
    with RISK_CONFIG.open(encoding="utf-8") as handle:
        config = json.load(handle)
    threshold = float(args.threshold if args.threshold is not None else config["selected_threshold"])
    args.output_dir.mkdir(parents=True, exist_ok=True)
    detector = WatchDogDetector(args.model)
    model_sha256 = hashlib.sha256(args.model.read_bytes()).hexdigest()
    summaries = []
    for name, path in SPLITS.items():
        print(f"Evaluating {name} using {path} (threshold={threshold:.4f})", flush=True)
        metrics, _, _ = evaluate(name, path, detector, threshold, args.sample_size,
                                 args.seed, args.batch_size, args.review_limit, args.output_dir)
        summaries.append(metrics)
    overlap_path = DATA / "analysis" / "split_domain_overlap.csv"
    overlap = pd.read_csv(overlap_path).to_dict(orient="records") if overlap_path.is_file() else None
    time_fields = []
    for path in SPLITS.values():
        fields = {str(field).strip().lower() for field in pd.read_csv(path, nrows=0).columns}
        time_fields.extend(sorted(fields & TIMESTAMP_NAMES))
    report = {
        "title": "AI WatchDog frozen URL model evaluation",
        "generated_at_utc": pd.Timestamp.now(tz="UTC").isoformat(),
        "model_path": str(args.model), "model_sha256": model_sha256,
        "threshold": threshold, "threshold_source": "CLI override" if args.threshold is not None else "frozen Phase 4 risk_engine_config.json",
        "model_retrained": False, "threshold_tuned": False,
        "timestamp_columns_found": sorted(set(time_fields)),
        "temporal_evaluation": "NOT_PERFORMED; candidate time columns require provenance review" if time_fields else "UNAVAILABLE_NO_RELIABLE_TIMESTAMP",
        "domain_overlap_audit": overlap,
        "splits": summaries,
        "label_review": "False-positive and false-negative queues are generated for manual adjudication; no labels are treated as reviewed by this script.",
        "privacy": "Review CSVs omit credentials, query, fragment, and sensitive/opaque path segments by default; url_sha256 preserves a join key.",
    }
    (args.output_dir / "evaluation_summary.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    lines = ["# AI WatchDog frozen URL model evaluation", "", f"- Generated: {report['generated_at_utc']}",
             f"- Model SHA-256: `{model_sha256}`", f"- Threshold: `{threshold:.4f}` ({report['threshold_source']})",
             "- Retraining or threshold tuning: **not performed**", f"- Temporal evaluation: **{report['temporal_evaluation']}**",
             "- Domain overlap audit is read from `data/analysis/split_domain_overlap.csv`; review it with the split design before interpreting the results.",
             "", "| Split | Rows | Domains | Precision (95% CI) | Recall (95% CI) | FPR (95% CI) | FNR | F1 | ROC-AUC | PR-AUC | Brier | ECE |",
             "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for row in summaries:
        lines.append(f"| {row['dataset']} | {row['rows']} | {row['unique_domains']} | {row['precision']:.4f} ({row['precision_95ci_low']:.4f}–{row['precision_95ci_high']:.4f}) | {row['recall']:.4f} ({row['recall_95ci_low']:.4f}–{row['recall_95ci_high']:.4f}) | {row['false_positive_rate']:.4f} ({row['fpr_95ci_low']:.4f}–{row['fpr_95ci_high']:.4f}) | {row['false_negative_rate']:.4f} | {row['f1']:.4f} | {row['roc_auc']:.4f} | {row['pr_auc']:.4f} | {row['brier_score']:.4f} | {row['expected_calibration_error_10_bins']:.4f} |")
    time_note = ("Candidate time-like columns exist, but this script does not treat them as reliable until provenance, timezone, and collection semantics are reviewed." if time_fields
                 else "The current dataset has no reliable timestamps, so these results are not temporal validation.")
    lines += ["", "The confidence intervals are row-level Wilson intervals; they do not account for correlation among URLs from the same domain. Domain-separated scores are reported separately. " + time_note,
              "", "Each split also produces a prediction CSV, a per-domain review summary, and a privacy-reduced false-positive/false-negative adjudication queue. Fill `review_label`, `reviewer`, and `review_notes` only after manual review. The script does not apply adjudicated labels to training or alter the model.", ""]
    (args.output_dir / "evaluation_report.md").write_text("\n".join(lines), encoding="utf-8")
    print(f"Saved evaluation artifacts to {args.output_dir}", flush=True)


if __name__ == "__main__":
    main()
