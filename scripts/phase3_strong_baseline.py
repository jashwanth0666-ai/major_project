"""
AI WatchDog - Phase 3: Strong Baseline Model Benchmark

Models:
1. Logistic Regression - linear baseline
2. Random Forest - interpretable tree baseline
3. XGBoost - benchmark gradient boosting model
4. LightGBM - primary candidate for desktop deployment

Phase 2 engineered URL features are recreated automatically from each split.

Data rules:
- source is provenance only, never an ML feature.
- domain is used for grouping/splitting, never a raw ML feature.
- test and unseen-domain test are NOT used for model selection.
- validation F1 is the primary selection metric.
- PR-AUC is used as a secondary metric.
- The final selected model is evaluated once on test and unseen-domain data.

Outputs:
data/phase3/
    validation_results.csv
    final_results.csv
    phase3_report.txt
    phase3_metadata.json
    models/*.joblib
"""

from pathlib import Path
import gc
import json
import time
import warnings

import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    average_precision_score,
    confusion_matrix,
)

warnings.filterwarnings("ignore")

BASE_DIR = Path(__file__).resolve().parent
SPLIT_DIR = BASE_DIR / "data" / "splits"
OUTPUT_DIR = BASE_DIR / "data" / "phase3"
MODEL_DIR = OUTPUT_DIR / "models"

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
MODEL_DIR.mkdir(parents=True, exist_ok=True)

TRAIN_PATH = SPLIT_DIR / "train.csv"
VAL_PATH = SPLIT_DIR / "validation.csv"
TEST_PATH = SPLIT_DIR / "test.csv"
UNSEEN_PATH = SPLIT_DIR / "unseen_domain_test.csv"

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


def entropy_of_string(value):
    if not value:
        return 0.0

    counts = pd.Series(list(value)).value_counts().to_numpy(dtype=np.float64)
    probabilities = counts / counts.sum()

    return float(-(probabilities * np.log2(probabilities)).sum())


def engineer_features(df):
    """Recreate the engineered features from Phase 2."""

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
        query.str.count("&") + 1
    )

    df["domain_digit_count"] = domain.str.count(r"\d")

    df["domain_entropy"] = domain.map(entropy_of_string).astype(np.float32)

    path = url.str.extract(
        r"^[a-zA-Z][a-zA-Z0-9+\-.]*://[^/]*(/[^?#]*)?",
        expand=False
    ).fillna("")

    stripped_path = path.str.strip("/")

    df["path_segment_count"] = np.where(
        stripped_path.eq(""),
        0,
        stripped_path.str.count("/") + 1
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
    print(f"  Loading {path.name}...")

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
            f"{path} is missing required master columns: {missing}"
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
        "phishing": 1
    })

    if y.isna().any():
        bad = df.loc[y.isna(), "label"].value_counts().to_dict()
        raise ValueError(f"Unexpected labels in {path}: {bad}")

    y = y.astype(np.int8).to_numpy()

    print(
        f"    rows={len(y):,} | "
        f"benign={(y == 0).sum():,} | "
        f"phishing={(y == 1).sum():,}"
    )

    del df
    gc.collect()

    return X, y


def evaluate(name, model, X, y, split):
    start = time.time()

    probability = model.predict_proba(X)[:, 1]
    prediction = (probability >= 0.50).astype(np.int8)

    tn, fp, fn, tp = confusion_matrix(
        y,
        prediction,
        labels=[0, 1]
    ).ravel()

    result = {
        "model": name,
        "split": split,
        "threshold": 0.50,
        "accuracy": accuracy_score(y, prediction),
        "precision": precision_score(y, prediction, zero_division=0),
        "recall": recall_score(y, prediction, zero_division=0),
        "f1": f1_score(y, prediction, zero_division=0),
        "roc_auc": roc_auc_score(y, probability),
        "pr_auc": average_precision_score(y, probability),
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
        "evaluation_seconds": time.time() - start,
    }

    print(
        f"    {split:20s} "
        f"F1={result['f1']:.4f} | "
        f"Precision={result['precision']:.4f} | "
        f"Recall={result['recall']:.4f} | "
        f"ROC-AUC={result['roc_auc']:.4f} | "
        f"PR-AUC={result['pr_auc']:.4f}"
    )

    return result, probability


def build_models(y_train):
    models = {}

    # 1. Logistic Regression
    models["logistic_regression"] = Pipeline([
        ("scaler", StandardScaler()),
        ("model", LogisticRegression(
            max_iter=500,
            class_weight="balanced",
            solver="lbfgs"
        ))
    ])

    # 2. Random Forest
    models["random_forest"] = RandomForestClassifier(
        n_estimators=250,
        max_depth=22,
        min_samples_leaf=3,
        max_features="sqrt",
        class_weight="balanced_subsample",
        n_jobs=-1,
        random_state=42
    )

    # Class imbalance ratio for boosting models.
    positive = max(int((y_train == 1).sum()), 1)
    negative = max(int((y_train == 0).sum()), 1)
    scale_pos_weight = negative / positive

    # 3. XGBoost
    try:
        from xgboost import XGBClassifier

        models["xgboost"] = XGBClassifier(
            n_estimators=500,
            max_depth=8,
            learning_rate=0.06,
            subsample=0.85,
            colsample_bytree=0.85,
            min_child_weight=5,
            reg_alpha=0.0,
            reg_lambda=1.0,
            scale_pos_weight=scale_pos_weight,
            objective="binary:logistic",
            eval_metric="logloss",
            tree_method="hist",
            n_jobs=-1,
            random_state=42
        )

    except ImportError:
        print(
            "\nWARNING: XGBoost is not installed. "
            "Run: pip install xgboost"
        )

    # 4. LightGBM
    try:
        from lightgbm import LGBMClassifier

        models["lightgbm"] = LGBMClassifier(
            n_estimators=500,
            learning_rate=0.05,
            num_leaves=63,
            max_depth=-1,
            min_child_samples=40,
            subsample=0.85,
            colsample_bytree=0.85,
            reg_alpha=0.0,
            reg_lambda=1.0,
            scale_pos_weight=scale_pos_weight,
            objective="binary",
            n_jobs=-1,
            random_state=42,
            verbosity=-1
        )

    except ImportError:
        print(
            "\nWARNING: LightGBM is not installed. "
            "Run: pip install lightgbm"
        )

    return models


def main():

    total_start = time.time()

    print("=" * 76)
    print("AI WatchDog - PHASE 3 STRONG BASELINE MODEL BENCHMARK")
    print("=" * 76)

    print("\nModels:")
    print("  1. Logistic Regression  -> linear baseline")
    print("  2. Random Forest        -> explainable tree baseline")
    print("  3. XGBoost              -> benchmark boosting model")
    print("  4. LightGBM             -> primary desktop candidate")

    print("\nPhase 2 features are recreated automatically from URL/domain.")

    for path in [
        TRAIN_PATH,
        VAL_PATH,
        TEST_PATH,
        UNSEEN_PATH
    ]:
        if not path.exists():
            raise FileNotFoundError(f"Missing split: {path}")

    # ---------------------------------------------------------------
    # STEP 1
    # ---------------------------------------------------------------

    print("\n[1/6] Loading domain-aware datasets...")

    X_train, y_train = load_split(TRAIN_PATH)
    X_val, y_val = load_split(VAL_PATH)
    X_test, y_test = load_split(TEST_PATH)
    X_unseen, y_unseen = load_split(UNSEEN_PATH)

    print("\nDataset shapes:")
    print(f"  Train:              {X_train.shape}")
    print(f"  Validation:         {X_val.shape}")
    print(f"  Test:               {X_test.shape}")
    print(f"  Unseen-domain test: {X_unseen.shape}")

    # ---------------------------------------------------------------
    # STEP 2
    # ---------------------------------------------------------------

    print("\n[2/6] Building benchmark models...")

    models = build_models(y_train)

    print("\nModels available:")
    for name in models:
        print(f"  - {name}")

    # ---------------------------------------------------------------
    # STEP 3
    # ---------------------------------------------------------------

    print("\n[3/6] Training + validation evaluation...")

    validation_results = []
    trained_models = {}

    for name, model in models.items():

        print("\n" + "-" * 76)
        print(f"TRAINING: {name}")
        print("-" * 76)

        start = time.time()

        if name == "logistic_regression":
            model.fit(X_train, y_train)

        elif name in ["random_forest", "xgboost", "lightgbm"]:
            model.fit(X_train, y_train)

        trained_models[name] = model

        training_seconds = time.time() - start

        print(f"  Training time: {training_seconds:.1f}s")

        result, _ = evaluate(
            name,
            model,
            X_val,
            y_val,
            "validation"
        )

        result["training_seconds"] = training_seconds

        validation_results.append(result)

        joblib.dump(
            model,
            MODEL_DIR / f"{name}.joblib"
        )

        print(
            f"  Saved: {MODEL_DIR / f'{name}.joblib'}"
        )

    validation_df = pd.DataFrame(validation_results)

    validation_df = validation_df.sort_values(
        ["f1", "pr_auc", "roc_auc"],
        ascending=False
    )

    validation_df.to_csv(
        OUTPUT_DIR / "validation_results.csv",
        index=False
    )

    # ---------------------------------------------------------------
    # STEP 4
    # ---------------------------------------------------------------

    print("\n[4/6] Selecting primary candidate...")

    winner_name = validation_df.iloc[0]["model"]

    print(f"\n  PRIMARY CANDIDATE: {winner_name}")
    print(
        f"  Validation F1:     "
        f"{validation_df.iloc[0]['f1']:.4f}"
    )
    print(
        f"  Validation Recall: "
        f"{validation_df.iloc[0]['recall']:.4f}"
    )
    print(
        f"  Validation PR-AUC: "
        f"{validation_df.iloc[0]['pr_auc']:.4f}"
    )

    # ---------------------------------------------------------------
    # STEP 5
    # ---------------------------------------------------------------

    print("\n[5/6] Final evaluation on untouched test sets...")

    winner = trained_models[winner_name]

    test_result, test_probability = evaluate(
        winner_name,
        winner,
        X_test,
        y_test,
        "test"
    )

    unseen_result, unseen_probability = evaluate(
        winner_name,
        winner,
        X_unseen,
        y_unseen,
        "unseen_domain_test"
    )

    final_results = pd.DataFrame([
        test_result,
        unseen_result
    ])

    final_results.to_csv(
        OUTPUT_DIR / "final_results.csv",
        index=False
    )

    pd.DataFrame({
        "actual": y_test,
        "phishing_probability": test_probability,
        "prediction_at_0_50": (
            test_probability >= 0.50
        ).astype(int)
    }).to_csv(
        OUTPUT_DIR / "winner_test_predictions.csv",
        index=False
    )

    pd.DataFrame({
        "actual": y_unseen,
        "phishing_probability": unseen_probability,
        "prediction_at_0_50": (
            unseen_probability >= 0.50
        ).astype(int)
    }).to_csv(
        OUTPUT_DIR / "winner_unseen_predictions.csv",
        index=False
    )

    # ---------------------------------------------------------------
    # STEP 6
    # ---------------------------------------------------------------

    print("\n[6/6] Generating Phase 3 report...")

    f1_gap = test_result["f1"] - unseen_result["f1"]
    auc_gap = test_result["roc_auc"] - unseen_result["roc_auc"]

    report = []

    report.append(
        "AI WatchDog - PHASE 3 STRONG BASELINE MODEL REPORT"
    )
    report.append("=" * 68)
    report.append("")
    report.append(f"Training rows: {len(y_train):,}")
    report.append(f"Validation rows: {len(y_val):,}")
    report.append(f"Test rows: {len(y_test):,}")
    report.append(
        f"Unseen-domain test rows: {len(y_unseen):,}"
    )
    report.append(f"Features: {len(FEATURES)}")
    report.append("")
    report.append("MODELS")
    report.append("-" * 68)
    report.append("Logistic Regression - linear baseline")
    report.append("Random Forest - explainable tree baseline")
    report.append("XGBoost - benchmark boosting model")
    report.append("LightGBM - primary desktop deployment candidate")
    report.append("")
    report.append("FEATURES")
    report.append("-" * 68)

    for i, feature in enumerate(FEATURES, 1):
        report.append(f"{i:02d}. {feature}")

    report.append("")
    report.append("VALIDATION MODEL COMPARISON")
    report.append("-" * 68)

    for _, row in validation_df.iterrows():
        report.append(
            f"{row['model']}: "
            f"F1={row['f1']:.4f}, "
            f"Precision={row['precision']:.4f}, "
            f"Recall={row['recall']:.4f}, "
            f"ROC-AUC={row['roc_auc']:.4f}, "
            f"PR-AUC={row['pr_auc']:.4f}"
        )

    report.append("")
    report.append(f"SELECTED MODEL: {winner_name}")
    report.append("")
    report.append("FINAL TEST")
    report.append("-" * 68)
    report.append(
        f"F1={test_result['f1']:.4f}, "
        f"Precision={test_result['precision']:.4f}, "
        f"Recall={test_result['recall']:.4f}, "
        f"ROC-AUC={test_result['roc_auc']:.4f}, "
        f"PR-AUC={test_result['pr_auc']:.4f}"
    )

    report.append("")
    report.append("FINAL UNSEEN-DOMAIN TEST")
    report.append("-" * 68)
    report.append(
        f"F1={unseen_result['f1']:.4f}, "
        f"Precision={unseen_result['precision']:.4f}, "
        f"Recall={unseen_result['recall']:.4f}, "
        f"ROC-AUC={unseen_result['roc_auc']:.4f}, "
        f"PR-AUC={unseen_result['pr_auc']:.4f}"
    )

    report.append("")
    report.append("GENERALIZATION")
    report.append("-" * 68)
    report.append(f"F1 gap (test - unseen): {f1_gap:.4f}")
    report.append(f"ROC-AUC gap: {auc_gap:.4f}")

    report.append("")
    report.append("IMPORTANT")
    report.append("-" * 68)
    report.append(
        "The 0.50 threshold is only a baseline threshold."
    )
    report.append(
        "Final threshold/risk levels must be optimized on validation data."
    )
    report.append(
        "Test and unseen-domain data were not used for model selection."
    )

    total_seconds = time.time() - total_start
    report.append("")
    report.append(f"Total runtime: {total_seconds:.1f} seconds")

    report_path = OUTPUT_DIR / "phase3_report.txt"

    report_path.write_text(
        "\n".join(report),
        encoding="utf-8"
    )

    metadata = {
        "phase": "3",
        "features": FEATURES,
        "models": list(models.keys()),
        "selected_model": winner_name,
        "selection_metric": "validation_f1",
        "secondary_selection_metric": "validation_pr_auc",
        "baseline_threshold": 0.50,
        "train_rows": int(len(y_train)),
        "validation_rows": int(len(y_val)),
        "test_rows": int(len(y_test)),
        "unseen_domain_rows": int(len(y_unseen)),
        "runtime_seconds": total_seconds,
    }

    (OUTPUT_DIR / "phase3_metadata.json").write_text(
        json.dumps(metadata, indent=2),
        encoding="utf-8"
    )

    print("\n" + "=" * 76)
    print("PHASE 3 COMPLETE")
    print("=" * 76)

    print(f"Selected model:       {winner_name}")
    print(f"Validation F1:        {validation_df.iloc[0]['f1']:.4f}")
    print(f"Test F1:              {test_result['f1']:.4f}")
    print(f"Unseen-domain F1:     {unseen_result['f1']:.4f}")
    print(f"Test ROC-AUC:         {test_result['roc_auc']:.4f}")
    print(f"Unseen ROC-AUC:       {unseen_result['roc_auc']:.4f}")
    print(f"Total runtime:        {total_seconds:.1f}s")

    print("\nOutputs:")
    print(f"  {OUTPUT_DIR / 'validation_results.csv'}")
    print(f"  {OUTPUT_DIR / 'final_results.csv'}")
    print(f"  {OUTPUT_DIR / 'phase3_report.txt'}")

    print("\nNext phase:")
    print("  Phase 4 = probability calibration + threshold optimization")
    print("=" * 76)


if __name__ == "__main__":
    main()
