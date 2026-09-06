"""
AI WatchDog - PHASE 5.2
Fast Inference Validation

Purpose:
    Validate the Phase 5 inference pipeline on a representative stratified
    sample instead of rerunning inference over 100k+ rows.

Tests:
    - Phase 5 inference accuracy on sampled test data
    - unseen-domain sampled performance
    - prediction/risk consistency
    - probability/risk distribution
    - inference latency
    - basic feature-pipeline sanity

Run:
    python phase5_validation.py

Optional:
    python phase5_validation.py --sample-size 1000
"""

from __future__ import annotations

import argparse
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

from phase5_inference import WatchDogDetector, risk_level


BASE_DIR = Path(__file__).resolve().parent

TEST_PATH = BASE_DIR / "data" / "splits" / "test.csv"
UNSEEN_PATH = BASE_DIR / "data" / "splits" / "unseen_domain_test.csv"
OUTPUT_DIR = BASE_DIR / "data" / "phase5"

RANDOM_STATE = 42
DEFAULT_SAMPLE_SIZE = 1000


def stratified_sample(df: pd.DataFrame, n: int) -> pd.DataFrame:
    """Return a label-stratified sample without modifying the source."""
    if len(df) <= n:
        return df.copy()

    if "label" not in df.columns:
        return df.sample(n=n, random_state=RANDOM_STATE)

    parts = []

    labels = df["label"].astype(str)
    unique_labels = labels.unique()

    for label in unique_labels:
        group = df[labels == label]
        count = max(1, round(n * len(group) / len(df)))
        count = min(count, len(group))
        parts.append(group.sample(count, random_state=RANDOM_STATE))

    result = pd.concat(parts)

    if len(result) > n:
        result = result.sample(n=n, random_state=RANDOM_STATE)

    return result.sample(frac=1, random_state=RANDOM_STATE).reset_index(drop=True)


def normalize_label(value: str) -> int:
    """Convert project labels to 0=benign, 1=phishing."""
    value = str(value).strip().lower()

    if value in {"phishing", "bad", "1", "true"}:
        return 1

    if value in {"benign", "good", "0", "false"}:
        return 0

    raise ValueError(f"Unknown label: {value}")


def validate_dataset(
    detector: WatchDogDetector,
    df: pd.DataFrame,
    dataset_name: str,
) -> tuple[pd.DataFrame, dict]:
    """Run inference and calculate validation metrics."""

    if "url" not in df.columns:
        raise ValueError(f"{dataset_name}: missing 'url' column")

    if "label" not in df.columns:
        raise ValueError(f"{dataset_name}: missing 'label' column")

    y_true = np.array([normalize_label(x) for x in df["label"]])

    probabilities = []
    predictions = []
    scores = []
    levels = []
    decisions = []

    start = time.perf_counter()

    for url in df["url"].astype(str):
        result = detector.predict(url)

        probabilities.append(result["phishing_probability"])
        predictions.append(1 if result["prediction"] == "PHISHING" else 0)
        scores.append(result["risk_score"])
        levels.append(result["risk_level"])
        decisions.append(result["decision"])

    elapsed = time.perf_counter() - start

    probabilities = np.array(probabilities)
    predictions = np.array(predictions)

    metrics = {
        "dataset": dataset_name,
        "rows": len(df),
        "accuracy": accuracy_score(y_true, predictions),
        "f1": f1_score(y_true, predictions, zero_division=0),
        "precision": precision_score(y_true, predictions, zero_division=0),
        "recall": recall_score(y_true, predictions, zero_division=0),
        "roc_auc": roc_auc_score(y_true, probabilities),
        "runtime_seconds": elapsed,
        "avg_ms_per_url": (elapsed / len(df)) * 1000,
        "urls_per_second": len(df) / elapsed if elapsed > 0 else 0,
    }

    result_df = df[["url", "label"]].copy()
    result_df["phishing_probability"] = probabilities
    result_df["risk_score"] = scores
    result_df["risk_level"] = levels
    result_df["prediction"] = np.where(
        predictions == 1,
        "PHISHING",
        "BENIGN",
    )
    result_df["decision"] = decisions

    # Consistency check: risk score must equal rounded probability * 100.
    expected_scores = np.clip(
        np.round(probabilities * 100),
        0,
        100,
    ).astype(int)

    metrics["risk_score_consistency"] = bool(
        np.array_equal(np.array(scores), expected_scores)
    )

    metrics["risk_level_consistency"] = bool(
        all(
            level == risk_level(int(score))
            for level, score in zip(levels, scores)
        )
    )

    return result_df, metrics


def print_report(metrics: list[dict], result_frames: list[pd.DataFrame]):
    print("\nAI WatchDog - PHASE 5.2 VALIDATION")
    print("=" * 70)

    for m in metrics:
        print(f"\n{m['dataset']}")
        print("-" * 70)
        print(f"Rows                  : {m['rows']:,}")
        print(f"Accuracy              : {m['accuracy']:.4f}")
        print(f"F1                    : {m['f1']:.4f}")
        print(f"Precision             : {m['precision']:.4f}")
        print(f"Recall                : {m['recall']:.4f}")
        print(f"ROC-AUC               : {m['roc_auc']:.4f}")
        print(f"Runtime               : {m['runtime_seconds']:.3f} sec")
        print(f"Average latency       : {m['avg_ms_per_url']:.3f} ms/URL")
        print(f"Throughput            : {m['urls_per_second']:.2f} URLs/sec")
        print(
            f"Risk-score consistency: "
            f"{'PASS' if m['risk_score_consistency'] else 'FAIL'}"
        )
        print(
            f"Risk-level consistency: "
            f"{'PASS' if m['risk_level_consistency'] else 'FAIL'}"
        )

        frame = result_frames[metrics.index(m)]

        print("\nRisk distribution:")
        print(
            frame["risk_level"]
            .value_counts()
            .sort_index()
            .to_string()
        )

        print("\nPrediction distribution:")
        print(frame["prediction"].value_counts().to_string())

    all_pass = all(
        m["risk_score_consistency"] and m["risk_level_consistency"]
        for m in metrics
    )

    print("\n" + "=" * 70)
    print(
        "PHASE 5.2 STATUS: "
        + ("PASS" if all_pass else "CHECK REQUIRED")
    )
    print("=" * 70)


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--sample-size",
        type=int,
        default=DEFAULT_SAMPLE_SIZE,
        help="Rows sampled from each dataset (default: 1000)",
    )

    parser.add_argument(
        "--model",
        type=Path,
        default=None,
        help="Optional Phase 4 model artifact path",
    )

    args = parser.parse_args()

    if not TEST_PATH.exists():
        raise FileNotFoundError(f"Missing test split: {TEST_PATH}")

    if not UNSEEN_PATH.exists():
        raise FileNotFoundError(f"Missing unseen split: {UNSEEN_PATH}")

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    detector = (
        WatchDogDetector(args.model)
        if args.model
        else WatchDogDetector()
    )

    print("Loading validation datasets...")
    test = pd.read_csv(TEST_PATH)
    unseen = pd.read_csv(UNSEEN_PATH)

    test_sample = stratified_sample(test, args.sample_size)
    unseen_sample = stratified_sample(unseen, args.sample_size)

    print(f"Test sample   : {len(test_sample):,} rows")
    print(f"Unseen sample : {len(unseen_sample):,} rows")
    print("Running inference...")

    test_results, test_metrics = validate_dataset(
        detector,
        test_sample,
        "TEST SAMPLE",
    )

    unseen_results, unseen_metrics = validate_dataset(
        detector,
        unseen_sample,
        "UNSEEN-DOMAIN SAMPLE",
    )

    test_out = OUTPUT_DIR / "validation_test_sample.csv"
    unseen_out = OUTPUT_DIR / "validation_unseen_sample.csv"

    test_results.to_csv(test_out, index=False)
    unseen_results.to_csv(unseen_out, index=False)

    report_path = OUTPUT_DIR / "phase5_validation_report.txt"

    with report_path.open("w", encoding="utf-8") as f:
        f.write("AI WatchDog - PHASE 5.2 VALIDATION REPORT\n")
        f.write("=" * 70 + "\n\n")

        for m in [test_metrics, unseen_metrics]:
            f.write(f"{m['dataset']}\n")
            f.write("-" * 70 + "\n")

            for key, value in m.items():
                f.write(f"{key}: {value}\n")

            f.write("\n")

    print_report(
        [test_metrics, unseen_metrics],
        [test_results, unseen_results],
    )

    print(f"\nSaved:")
    print(f"  {test_out}")
    print(f"  {unseen_out}")
    print(f"  {report_path}")


if __name__ == "__main__":
    main()
