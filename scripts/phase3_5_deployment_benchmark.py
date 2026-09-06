"""
AI WatchDog - PHASE 3.5 DEPLOYMENT BENCHMARK

Purpose:
- Reuse the Phase 3 trained models; DO NOT retrain.
- Compare predictive performance and desktop deployment characteristics.
- Measure FPR/FNR, inference latency, P50/P95 latency, throughput,
  serialized model size, and feature importance where available.

Models expected in:
    data/phase3/models/
        logistic_regression.joblib
        random_forest.joblib
        xgboost.joblib
        lightgbm.joblib

Splits expected in:
    data/splits/
        train.csv
        validation.csv
        test.csv
        unseen_domain_test.csv

Outputs:
    data/phase3_5/
        deployment_benchmark.csv
        feature_importance.csv
        deployment_benchmark_report.txt

Important:
- No test/unseen data is used to select thresholds or retrain models.
- Model selection remains based on validation performance plus deployment
  characteristics.
- The latency benchmark measures model inference only, excluding CSV loading
  and feature engineering.
"""

from pathlib import Path
import gc
import time
import warnings

import joblib
import numpy as np
import pandas as pd

from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

warnings.filterwarnings("ignore")

# ---------------------------------------------------------------------
# PATHS
# ---------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent

SPLIT_DIR = BASE_DIR / "data" / "splits"
MODEL_DIR = BASE_DIR / "data" / "phase3" / "models"
OUTPUT_DIR = BASE_DIR / "data" / "phase3_5"

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

TRAIN_PATH = SPLIT_DIR / "train.csv"
VAL_PATH = SPLIT_DIR / "validation.csv"
TEST_PATH = SPLIT_DIR / "test.csv"
UNSEEN_PATH = SPLIT_DIR / "unseen_domain_test.csv"

MODEL_NAMES = [
    "logistic_regression",
    "random_forest",
    "xgboost",
    "lightgbm",
]

FEATURES = [
    "url_length",
    "domain_length",
    "subdomain_count",
    "path_length",
    "query_length",
    "has_ip",
    "has_https",
    "has_at",
    "has_dash",
    "has_multiple_subdomains",
    "special_char_count",
    "digit_count",
    "entropy",
    "has_shortener",
    "suspicious_keyword_count",
    "dot_count",
    "slash_count",
    "hyphen_count",
    "percent_encoded_count",
    "query_parameter_count",
    "uppercase_count",
    "domain_digit_count",
    "domain_entropy",
    "path_segment_count",
    "digit_ratio",
]


# ---------------------------------------------------------------------
# FEATURE ENGINEERING
# ---------------------------------------------------------------------

def entropy_of_string(value):
    if not value:
        return 0.0

    counts = pd.Series(list(value)).value_counts().to_numpy(dtype=np.float64)
    probabilities = counts / counts.sum()

    return float(-(probabilities * np.log2(probabilities)).sum())


def engineer_features(df):
    """Recreate exactly the engineered Phase 2 feature family."""

    df = df.copy()

    url = df["url"].fillna("").astype(str)
    domain = df["domain"].fillna("").astype(str)

    df["dot_count"] = url.str.count(r"\.")
    df["slash_count"] = url.str.count("/")
    df["hyphen_count"] = url.str.count("-")
    df["percent_encoded_count"] = url.str.count(r"%[0-9A-Fa-f]{2}")
    df["uppercase_count"] = url.str.count(r"[A-Z]")

    query = url.str.extract(r"\?(.*)$", expand=False).fillna("")

    df["query_parameter_count"] = np.where(
        query.eq(""),
        0,
        query.str.count("&") + 1,
    )

    df["domain_digit_count"] = domain.str.count(r"\d")
    df["domain_entropy"] = domain.map(entropy_of_string).astype(np.float32)

    path = url.str.extract(
        r"^[a-zA-Z][a-zA-Z0-9+\-.]*://[^/]*(/[^?#]*)?",
        expand=False,
    ).fillna("")

    stripped_path = path.str.strip("/")

    df["path_segment_count"] = np.where(
        stripped_path.eq(""),
        0,
        stripped_path.str.count("/") + 1,
    )

    url_length = pd.to_numeric(
        df["url_length"], errors="coerce"
    ).replace(0, np.nan)

    df["digit_ratio"] = (
        pd.to_numeric(df["digit_count"], errors="coerce")
        / url_length
    ).fillna(0).astype(np.float32)

    return df


def load_split(path):
    print(f"Loading {path.name}...")

    df = pd.read_csv(path, low_memory=False)

    required = [
        "url",
        "label",
        "domain",
        "url_length",
        "domain_length",
        "subdomain_count",
        "path_length",
        "query_length",
        "has_ip",
        "has_https",
        "has_at",
        "has_dash",
        "has_multiple_subdomains",
        "special_char_count",
        "digit_count",
        "entropy",
        "has_shortener",
        "suspicious_keyword_count",
    ]

    missing = [c for c in required if c not in df.columns]

    if missing:
        raise ValueError(
            f"{path} is missing required columns: {missing}"
        )

    df = engineer_features(df)

    X = (
        df[FEATURES]
        .apply(pd.to_numeric, errors="coerce")
        .replace([np.inf, -np.inf], np.nan)
        .fillna(0)
        .astype(np.float32)
        .to_numpy()
    )

    y = df["label"].map({
        "benign": 0,
        "phishing": 1,
    })

    if y.isna().any():
        raise ValueError(
            f"Unexpected labels in {path}: "
            f"{df.loc[y.isna(), 'label'].value_counts().to_dict()}"
        )

    y = y.astype(np.int8).to_numpy()

    del df
    gc.collect()

    return X, y


# ---------------------------------------------------------------------
# METRICS
# ---------------------------------------------------------------------

def classification_metrics(y_true, probability, threshold=0.50):
    prediction = (probability >= threshold).astype(np.int8)

    tn, fp, fn, tp = confusion_matrix(
        y_true,
        prediction,
        labels=[0, 1],
    ).ravel()

    negatives = tn + fp
    positives = tp + fn

    fpr = fp / negatives if negatives else 0.0
    fnr = fn / positives if positives else 0.0

    return {
        "accuracy": accuracy_score(y_true, prediction),
        "precision": precision_score(
            y_true, prediction, zero_division=0
        ),
        "recall": recall_score(
            y_true, prediction, zero_division=0
        ),
        "f1": f1_score(
            y_true, prediction, zero_division=0
        ),
        "roc_auc": roc_auc_score(y_true, probability),
        "pr_auc": average_precision_score(y_true, probability),
        "fpr": fpr,
        "fnr": fnr,
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
    }


# ---------------------------------------------------------------------
# LATENCY
# ---------------------------------------------------------------------

def benchmark_latency(model, X):
    """
    Desktop-style single-URL inference benchmark.

    Uses a deterministic sample from the test set.
    Feature engineering is intentionally excluded because this measures
    the trained model's inference component only.

    Warm-up calls are excluded.
    """

    sample_size = min(1000, len(X))

    # Evenly spread samples through the test set rather than taking only
    # the first rows.
    indices = np.linspace(
        0,
        len(X) - 1,
        num=sample_size,
        dtype=int,
    )

    samples = X[indices]

    # Warm up model/runtime.
    for i in range(min(10, sample_size)):
        model.predict_proba(samples[i:i + 1])

    latencies_ms = []

    for i in range(sample_size):
        row = samples[i:i + 1]

        start = time.perf_counter()
        model.predict_proba(row)
        elapsed_ms = (time.perf_counter() - start) * 1000.0

        latencies_ms.append(elapsed_ms)

    latencies_ms = np.asarray(latencies_ms)

    batch_start = time.perf_counter()
    model.predict_proba(samples)
    batch_seconds = time.perf_counter() - batch_start

    throughput = (
        sample_size / batch_seconds
        if batch_seconds > 0
        else 0.0
    )

    return {
        "latency_mean_ms": float(np.mean(latencies_ms)),
        "latency_median_ms": float(np.median(latencies_ms)),
        "latency_p50_ms": float(np.percentile(latencies_ms, 50)),
        "latency_p95_ms": float(np.percentile(latencies_ms, 95)),
        "latency_p99_ms": float(np.percentile(latencies_ms, 99)),
        "latency_max_ms": float(np.max(latencies_ms)),
        "throughput_urls_per_sec": float(throughput),
        "latency_samples": int(sample_size),
    }


# ---------------------------------------------------------------------
# MODEL SIZE
# ---------------------------------------------------------------------

def model_size_mb(path):
    return path.stat().st_size / (1024 * 1024)


# ---------------------------------------------------------------------
# FEATURE IMPORTANCE
# ---------------------------------------------------------------------

def extract_feature_importance(model, model_name):
    """
    Extract native feature importance when supported.

    Logistic Regression uses absolute coefficient magnitude.
    Tree/boosting models use feature_importances_.
    """

    if model_name == "logistic_regression":
        estimator = model

        if hasattr(model, "named_steps"):
            estimator = model.named_steps.get("model", model)

        if not hasattr(estimator, "coef_"):
            return None

        values = np.abs(estimator.coef_[0])

    elif hasattr(model, "feature_importances_"):
        values = np.asarray(
            model.feature_importances_,
            dtype=np.float64,
        )

    else:
        return None

    if len(values) != len(FEATURES):
        return None

    importance = pd.DataFrame({
        "model": model_name,
        "feature": FEATURES,
        "importance": values,
    })

    importance["rank"] = (
        importance["importance"]
        .rank(method="min", ascending=False)
        .astype(int)
    )

    return importance.sort_values("rank")


# ---------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------

def main():

    total_start = time.perf_counter()

    print("=" * 76)
    print("AI WatchDog - PHASE 3.5 DEPLOYMENT BENCHMARK")
    print("=" * 76)

    # ---------------------------------------------------------------
    # Check files
    # ---------------------------------------------------------------

    print("\n[1/5] Checking existing Phase 3 models...")

    for model_name in MODEL_NAMES:
        path = MODEL_DIR / f"{model_name}.joblib"

        if not path.exists():
            raise FileNotFoundError(
                f"Missing trained model:\n{path}\n\n"
                "Run Phase 3 strong baseline first."
            )

        print(
            f"  {model_name:22s} "
            f"{model_size_mb(path):.2f} MB"
        )

    for path in [VAL_PATH, TEST_PATH, UNSEEN_PATH]:
        if not path.exists():
            raise FileNotFoundError(f"Missing split: {path}")

    # ---------------------------------------------------------------
    # Load data
    # ---------------------------------------------------------------

    print("\n[2/5] Loading evaluation datasets...")

    # Train is not needed for benchmarking.
    # Avoiding it saves memory and time.
    X_val, y_val = load_split(VAL_PATH)
    X_test, y_test = load_split(TEST_PATH)
    X_unseen, y_unseen = load_split(UNSEEN_PATH)

    print(f"  Validation:         {len(y_val):,}")
    print(f"  Test:               {len(y_test):,}")
    print(f"  Unseen-domain test: {len(y_unseen):,}")

    # ---------------------------------------------------------------
    # Benchmark models
    # ---------------------------------------------------------------

    print("\n[3/5] Benchmarking models...")

    benchmark_rows = []
    importance_frames = []

    for model_name in MODEL_NAMES:

        model_path = MODEL_DIR / f"{model_name}.joblib"

        print("\n" + "-" * 76)
        print(f"MODEL: {model_name}")
        print("-" * 76)

        load_start = time.perf_counter()
        model = joblib.load(model_path)
        load_seconds = time.perf_counter() - load_start

        print(f"  Load time: {load_seconds:.3f}s")

        # Validation
        val_start = time.perf_counter()
        val_probability = model.predict_proba(X_val)[:, 1]
        val_batch_seconds = time.perf_counter() - val_start

        val_metrics = classification_metrics(
            y_val,
            val_probability,
            threshold=0.50,
        )

        print(
            f"  Validation: "
            f"F1={val_metrics['f1']:.4f} | "
            f"Precision={val_metrics['precision']:.4f} | "
            f"Recall={val_metrics['recall']:.4f} | "
            f"PR-AUC={val_metrics['pr_auc']:.4f}"
        )

        # Test
        test_start = time.perf_counter()
        test_probability = model.predict_proba(X_test)[:, 1]
        test_batch_seconds = time.perf_counter() - test_start

        test_metrics = classification_metrics(
            y_test,
            test_probability,
            threshold=0.50,
        )

        print(
            f"  Test:       "
            f"F1={test_metrics['f1']:.4f} | "
            f"FPR={test_metrics['fpr']:.4f} | "
            f"FNR={test_metrics['fnr']:.4f}"
        )

        # Unseen-domain test
        unseen_start = time.perf_counter()
        unseen_probability = model.predict_proba(X_unseen)[:, 1]
        unseen_batch_seconds = time.perf_counter() - unseen_start

        unseen_metrics = classification_metrics(
            y_unseen,
            unseen_probability,
            threshold=0.50,
        )

        print(
            f"  Unseen:     "
            f"F1={unseen_metrics['f1']:.4f} | "
            f"FPR={unseen_metrics['fpr']:.4f} | "
            f"FNR={unseen_metrics['fnr']:.4f}"
        )

        # Single-URL latency
        print("  Measuring single-URL inference latency...")

        latency = benchmark_latency(
            model,
            X_test,
        )

        print(
            f"  Latency: "
            f"P50={latency['latency_p50_ms']:.3f} ms | "
            f"P95={latency['latency_p95_ms']:.3f} ms | "
            f"mean={latency['latency_mean_ms']:.3f} ms"
        )

        print(
            f"  Throughput: "
            f"{latency['throughput_urls_per_sec']:.1f} URLs/s"
        )

        # Feature importance
        importance = extract_feature_importance(
            model,
            model_name,
        )

        if importance is not None:
            importance_frames.append(importance)

            print("  Top 5 features:")

            for _, row in importance.head(5).iterrows():
                print(
                    f"    {int(row['rank']):2d}. "
                    f"{row['feature']:30s} "
                    f"{row['importance']:.6f}"
                )

        # Final row
        row = {
            "model": model_name,
            "model_size_mb": model_size_mb(model_path),
            "model_load_seconds": load_seconds,

            "validation_f1": val_metrics["f1"],
            "validation_precision": val_metrics["precision"],
            "validation_recall": val_metrics["recall"],
            "validation_roc_auc": val_metrics["roc_auc"],
            "validation_pr_auc": val_metrics["pr_auc"],
            "validation_fpr": val_metrics["fpr"],
            "validation_fnr": val_metrics["fnr"],

            "test_f1": test_metrics["f1"],
            "test_precision": test_metrics["precision"],
            "test_recall": test_metrics["recall"],
            "test_roc_auc": test_metrics["roc_auc"],
            "test_pr_auc": test_metrics["pr_auc"],
            "test_fpr": test_metrics["fpr"],
            "test_fnr": test_metrics["fnr"],

            "unseen_f1": unseen_metrics["f1"],
            "unseen_precision": unseen_metrics["precision"],
            "unseen_recall": unseen_metrics["recall"],
            "unseen_roc_auc": unseen_metrics["roc_auc"],
            "unseen_pr_auc": unseen_metrics["pr_auc"],
            "unseen_fpr": unseen_metrics["fpr"],
            "unseen_fnr": unseen_metrics["fnr"],

            "latency_mean_ms": latency["latency_mean_ms"],
            "latency_median_ms": latency["latency_median_ms"],
            "latency_p50_ms": latency["latency_p50_ms"],
            "latency_p95_ms": latency["latency_p95_ms"],
            "latency_p99_ms": latency["latency_p99_ms"],
            "latency_max_ms": latency["latency_max_ms"],
            "throughput_urls_per_sec": latency[
                "throughput_urls_per_sec"
            ],

            "test_batch_seconds": test_batch_seconds,
            "unseen_batch_seconds": unseen_batch_seconds,
        }

        benchmark_rows.append(row)

        del model
        gc.collect()

    # ---------------------------------------------------------------
    # Save results
    # ---------------------------------------------------------------

    print("\n[4/5] Saving benchmark results...")

    benchmark_df = pd.DataFrame(benchmark_rows)

    benchmark_df = benchmark_df.sort_values(
        [
            "validation_f1",
            "validation_pr_auc",
            "unseen_f1",
        ],
        ascending=False,
    )

    benchmark_path = OUTPUT_DIR / "deployment_benchmark.csv"
    benchmark_df.to_csv(
        benchmark_path,
        index=False,
    )

    if importance_frames:
        importance_df = pd.concat(
            importance_frames,
            ignore_index=True,
        )

        importance_df.to_csv(
            OUTPUT_DIR / "feature_importance.csv",
            index=False,
        )

    # ---------------------------------------------------------------
    # Deployment recommendation
    # ---------------------------------------------------------------

    print("\n[5/5] Generating deployment report...")

    # Primary ranking: validation F1.
    # Deployment metrics are reported alongside it rather than hidden
    # inside an arbitrary weighted score.
    selected = benchmark_df.iloc[0]

    report = []

    report.append(
        "AI WatchDog - PHASE 3.5 DEPLOYMENT BENCHMARK REPORT"
    )
    report.append("=" * 76)
    report.append("")
    report.append(
        "Purpose: compare predictive performance and deployment "
        "characteristics of the four Phase 3 models."
    )
    report.append("")
    report.append("MODELS")
    report.append("-" * 76)
    report.append(
        "Logistic Regression = linear baseline"
    )
    report.append(
        "Random Forest = explainable tree baseline"
    )
    report.append(
        "XGBoost = gradient boosting benchmark"
    )
    report.append(
        "LightGBM = desktop deployment candidate"
    )
    report.append("")
    report.append("IMPORTANT")
    report.append("-" * 76)
    report.append(
        "No model was retrained in Phase 3.5."
    )
    report.append(
        "The 0.50 threshold is still only a baseline threshold."
    )
    report.append(
        "Threshold optimization belongs to Phase 4 and must use "
        "validation data."
    )
    report.append(
        "Test and unseen-domain results are reported for comparison, "
        "not for tuning."
    )
    report.append("")
    report.append("DEPLOYMENT COMPARISON")
    report.append("-" * 76)

    for _, row in benchmark_df.iterrows():
        report.append(
            f"{row['model']}: "
            f"Val F1={row['validation_f1']:.4f}, "
            f"Test F1={row['test_f1']:.4f}, "
            f"Unseen F1={row['unseen_f1']:.4f}, "
            f"Unseen FPR={row['unseen_fpr']:.4f}, "
            f"P50={row['latency_p50_ms']:.3f} ms, "
            f"P95={row['latency_p95_ms']:.3f} ms, "
            f"Size={row['model_size_mb']:.2f} MB"
        )

    report.append("")
    report.append("DETAILED METRICS")
    report.append("-" * 76)

    for _, row in benchmark_df.iterrows():

        report.append("")
        report.append(row["model"])

        report.append(
            f"  Model size: {row['model_size_mb']:.2f} MB"
        )

        report.append(
            f"  Validation: "
            f"F1={row['validation_f1']:.4f}, "
            f"Precision={row['validation_precision']:.4f}, "
            f"Recall={row['validation_recall']:.4f}, "
            f"ROC-AUC={row['validation_roc_auc']:.4f}, "
            f"PR-AUC={row['validation_pr_auc']:.4f}, "
            f"FPR={row['validation_fpr']:.4f}"
        )

        report.append(
            f"  Test: "
            f"F1={row['test_f1']:.4f}, "
            f"Precision={row['test_precision']:.4f}, "
            f"Recall={row['test_recall']:.4f}, "
            f"ROC-AUC={row['test_roc_auc']:.4f}, "
            f"PR-AUC={row['test_pr_auc']:.4f}, "
            f"FPR={row['test_fpr']:.4f}, "
            f"FNR={row['test_fnr']:.4f}"
        )

        report.append(
            f"  Unseen: "
            f"F1={row['unseen_f1']:.4f}, "
            f"Precision={row['unseen_precision']:.4f}, "
            f"Recall={row['unseen_recall']:.4f}, "
            f"ROC-AUC={row['unseen_roc_auc']:.4f}, "
            f"PR-AUC={row['unseen_pr_auc']:.4f}, "
            f"FPR={row['unseen_fpr']:.4f}, "
            f"FNR={row['unseen_fnr']:.4f}"
        )

        report.append(
            f"  Latency: "
            f"mean={row['latency_mean_ms']:.3f} ms, "
            f"P50={row['latency_p50_ms']:.3f} ms, "
            f"P95={row['latency_p95_ms']:.3f} ms, "
            f"P99={row['latency_p99_ms']:.3f} ms"
        )

        report.append(
            f"  Throughput: "
            f"{row['throughput_urls_per_sec']:.1f} URLs/s"
        )

    report.append("")
    report.append("CURRENT MODEL RANKING")
    report.append("-" * 76)
    report.append(
        "Ranking criterion: validation F1, followed by validation PR-AUC "
        "and unseen-domain F1."
    )

    for rank, (_, row) in enumerate(
        benchmark_df.iterrows(),
        start=1,
    ):
        report.append(
            f"{rank}. {row['model']}"
        )

    report.append("")
    report.append(
        f"CURRENT PERFORMANCE LEADER: {selected['model']}"
    )
    report.append(
        f"Validation F1: {selected['validation_f1']:.4f}"
    )

    report.append("")
    report.append("DEPLOYMENT DECISION")
    report.append("-" * 76)
    report.append(
        "Phase 3.5 does not automatically override the validation-F1 "
        "winner."
    )
    report.append(
        "Use the latency, model size, false-positive rate and "
        "unseen-domain performance to make the final deployment decision."
    )
    report.append(
        "If two models have similar predictive performance, prefer the "
        "smaller/faster model for desktop deployment."
    )
    report.append("")
    report.append(
        "Phase 4 should perform probability calibration and validation-only "
        "threshold optimization before final risk bands are frozen."
    )

    report_path = OUTPUT_DIR / "deployment_benchmark_report.txt"
    report_path.write_text(
        "\n".join(report),
        encoding="utf-8",
    )

    total_seconds = time.perf_counter() - total_start

    print("\n" + "=" * 76)
    print("PHASE 3.5 COMPLETE")
    print("=" * 76)

    print("\nRanking:")
    for rank, (_, row) in enumerate(
        benchmark_df.iterrows(),
        start=1,
    ):
        print(
            f"{rank}. {row['model']:22s} "
            f"Val F1={row['validation_f1']:.4f} | "
            f"Unseen F1={row['unseen_f1']:.4f} | "
            f"P95={row['latency_p95_ms']:.3f} ms | "
            f"Size={row['model_size_mb']:.2f} MB"
        )

    print(f"\nCurrent performance leader: {selected['model']}")
    print(f"Total runtime: {total_seconds:.1f}s")

    print("\nOutputs:")
    print(f"  {benchmark_path}")
    if importance_frames:
        print(f"  {OUTPUT_DIR / 'feature_importance.csv'}")
    print(f"  {report_path}")

    print("\nNEXT:")
    print("  Phase 4 = probability calibration + threshold optimization")
    print("=" * 76)


if __name__ == "__main__":
    main()
