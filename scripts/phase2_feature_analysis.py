"""
AI WatchDog - Phase 2: Feature Engineering & Feature Analysis

Input:
    data/splits/train.csv
    data/splits/validation.csv
    data/splits/test.csv
    data/splits/unseen_domain_test.csv

Outputs:
    data/phase2/
        feature_statistics.csv
        class_feature_comparison.csv
        correlation_matrix.csv
        high_correlation_pairs.csv
        tree_feature_importance.csv
        security_feature_analysis.csv
        engineered_feature_statistics.csv
        phase2_selected_features.txt
        phase2_report.txt

Notes:
- Raw URL/domain/source are NOT used as ML predictors.
- Analysis is performed primarily on TRAIN to avoid test-set feature-selection leakage.
- Validation/test/unseen-domain are used only for final distribution checks.
"""

from pathlib import Path
import math
import re
import warnings

import numpy as np
import pandas as pd
from sklearn.ensemble import ExtraTreesClassifier

warnings.filterwarnings("ignore")

BASE = Path("data")
SPLIT_DIR = BASE / "splits"
OUT = BASE / "phase2"
OUT.mkdir(parents=True, exist_ok=True)

TRAIN = SPLIT_DIR / "train.csv"
VAL = SPLIT_DIR / "validation.csv"
TEST = SPLIT_DIR / "test.csv"
UNSEEN = SPLIT_DIR / "unseen_domain_test.csv"

REQUIRED = [
    "url", "label", "source", "domain", "tld",
    "url_length", "domain_length", "subdomain_count",
    "path_length", "query_length", "has_ip", "has_https",
    "has_at", "has_dash", "has_multiple_subdomains",
    "special_char_count", "digit_count", "entropy",
    "has_shortener", "suspicious_keyword_count"
]

BASE_FEATURES = [
    "url_length", "domain_length", "subdomain_count",
    "path_length", "query_length", "has_ip", "has_https",
    "has_at", "has_dash", "has_multiple_subdomains",
    "special_char_count", "digit_count", "entropy",
    "has_shortener", "suspicious_keyword_count"
]


def safe_entropy(text):
    if not text:
        return 0.0
    counts = pd.Series(list(text)).value_counts()
    p = counts / counts.sum()
    return float(-(p * np.log2(p)).sum())


def engineer_features(df):
    """Add compact URL/domain/path/query character features."""
    out = df.copy()

    url = out["url"].fillna("").astype(str)
    domain = out["domain"].fillna("").astype(str)

    # Character counts
    out["dot_count"] = url.str.count(r"\.")
    out["slash_count"] = url.str.count("/")
    out["hyphen_count"] = url.str.count("-")
    out["underscore_count"] = url.str.count("_")
    out["percent_encoded_count"] = url.str.count("%[0-9A-Fa-f]{2}")
    out["double_slash_count"] = url.str.count("//")
    out["colon_count"] = url.str.count(":")
    out["semicolon_count"] = url.str.count(";")
    out["equals_count"] = url.str.count("=")
    out["ampersand_count"] = url.str.count("&")
    out["question_mark_count"] = url.str.count(r"\?")
    out["at_count"] = url.str.count("@")

    # Character composition
    out["uppercase_count"] = url.str.count(r"[A-Z]")
    out["lowercase_count"] = url.str.count(r"[a-z]")
    out["letter_count"] = url.str.count(r"[A-Za-z]")
    out["url_digit_count"] = url.str.count(r"\d")
    out["url_special_count"] = url.str.count(r"[^A-Za-z0-9]")

    out["domain_digit_count"] = domain.str.count(r"\d")
    out["domain_hyphen_count"] = domain.str.count("-")
    out["domain_dot_count"] = domain.str.count(r"\.")
    out["domain_special_count"] = domain.str.count(r"[^A-Za-z0-9.-]")

    # Ratios
    denom = out["url_length"].replace(0, np.nan)
    out["digit_ratio"] = (out["digit_count"] / denom).fillna(0)
    out["special_char_ratio"] = (
        out["special_char_count"] / denom
    ).fillna(0)
    out["letter_ratio"] = (
        out["letter_count"] / denom
    ).fillna(0)

    # Entropy by components
    out["domain_entropy"] = domain.map(safe_entropy).astype("float32")

    # Path/query counts
    out["path_segment_count"] = url.str.extract(
        r"^(?:https?://)?[^/]+(/[^?#]*)?", expand=False
    ).fillna("").str.strip("/").str.count("/") + (
        url.str.contains(r"^(?:https?://)?[^/]+/[^?#]+", regex=True)
    ).astype(int)

    out["query_parameter_count"] = np.where(
        url.str.contains(r"\?", regex=True),
        url.str.split("?", n=1).str[1].fillna("").str.count("&") + 1,
        0
    )

    # Binary indicators
    out["has_percent_encoding"] = (
        out["percent_encoded_count"] > 0
    ).astype("int8")
    out["has_many_digits"] = (out["url_digit_count"] >= 5).astype("int8")
    out["has_long_url"] = (out["url_length"] >= 100).astype("int8")
    out["has_long_domain"] = (out["domain_length"] >= 30).astype("int8")

    return out


def feature_columns(df):
    excluded = {
        "url", "label", "source", "domain", "tld"
    }
    cols = []
    for c in df.columns:
        if c not in excluded and pd.api.types.is_numeric_dtype(df[c]):
            cols.append(c)
    return cols


def class_comparison(df, features):
    rows = []
    for f in features:
        benign = df.loc[df["label"] == "benign", f].dropna()
        phishing = df.loc[df["label"] == "phishing", f].dropna()

        if len(benign) == 0 or len(phishing) == 0:
            continue

        bmean = benign.mean()
        pmean = phishing.mean()
        bmed = benign.median()
        pmed = phishing.median()

        pooled = math.sqrt(
            max(benign.var(ddof=1), 0) +
            max(phishing.var(ddof=1), 0)
        )

        standardized = (
            (pmean - bmean) / pooled if pooled > 0 else 0
        )

        rows.append({
            "feature": f,
            "benign_mean": bmean,
            "phishing_mean": pmean,
            "benign_median": bmed,
            "phishing_median": pmed,
            "difference_mean": pmean - bmean,
            "absolute_difference": abs(pmean - bmean),
            "standardized_difference": standardized,
        })

    result = pd.DataFrame(rows)
    if not result.empty:
        result["abs_standardized_difference"] = result[
            "standardized_difference"
        ].abs()
        result = result.sort_values(
            "abs_standardized_difference", ascending=False
        )
    return result


def security_analysis(df):
    security_features = [
        f for f in [
            "has_ip", "has_https", "has_at", "has_dash",
            "has_multiple_subdomains", "has_shortener",
            "has_percent_encoding", "has_many_digits",
            "has_long_url", "has_long_domain"
        ] if f in df.columns
    ]

    rows = []
    for f in security_features:
        for label in ["benign", "phishing"]:
            subset = df[df["label"] == label]
            if len(subset) == 0:
                continue
            rate = subset[f].mean()
            rows.append({
                "feature": f,
                "label": label,
                "count": int(subset[f].sum()),
                "total": len(subset),
                "rate": rate
            })
    return pd.DataFrame(rows)


def main():
    print("=" * 65)
    print("AI WatchDog - PHASE 2 FEATURE ENGINEERING & ANALYSIS")
    print("=" * 65)

    if not TRAIN.exists():
        raise FileNotFoundError(
            f"Missing {TRAIN}. Run Phase 1.5 first."
        )

    print("\n[1/8] Loading training data...")
    train = pd.read_csv(TRAIN)
    missing = [c for c in REQUIRED if c not in train.columns]
    if missing:
        raise ValueError(f"Missing required columns: {missing}")

    print(f"Train rows: {len(train):,}")

    print("\n[2/8] Engineering additional features...")
    train = engineer_features(train)

    engineered = [
        c for c in train.columns
        if c not in REQUIRED
    ]

    all_features = feature_columns(train)

    # Ensure numeric and finite
    train[all_features] = train[all_features].replace(
        [np.inf, -np.inf], np.nan
    ).fillna(0)

    print(f"Base numeric features: {len(BASE_FEATURES)}")
    print(f"Engineered features: {len(engineered)}")
    print(f"Total candidate numeric features: {len(all_features)}")

    print("\n[3/8] Feature statistics...")
    stats = train[all_features].describe().T.reset_index()
    stats = stats.rename(columns={"index": "feature"})
    stats.to_csv(OUT / "feature_statistics.csv", index=False)

    print("\n[4/8] Benign vs phishing comparison...")
    comparison = class_comparison(train, all_features)
    comparison.to_csv(
        OUT / "class_feature_comparison.csv", index=False
    )

    print("\n[5/8] Correlation analysis...")
    corr = train[all_features].corr(numeric_only=True)
    corr.to_csv(OUT / "correlation_matrix.csv")

    pairs = []
    cols = list(corr.columns)
    for i in range(len(cols)):
        for j in range(i + 1, len(cols)):
            value = corr.iloc[i, j]
            if pd.notna(value) and abs(value) >= 0.90:
                pairs.append({
                    "feature_1": cols[i],
                    "feature_2": cols[j],
                    "correlation": value,
                    "absolute_correlation": abs(value)
                })

    pairs_df = pd.DataFrame(pairs).sort_values(
        "absolute_correlation", ascending=False
    ) if pairs else pd.DataFrame(
        columns=[
            "feature_1", "feature_2",
            "correlation", "absolute_correlation"
        ]
    )
    pairs_df.to_csv(
        OUT / "high_correlation_pairs.csv", index=False
    )

    print("\n[6/8] Tree-based feature importance...")
    X = train[all_features].astype("float32")
    y = (train["label"] == "phishing").astype("int8")

    # Fast, robust baseline importance.
    # 250 trees is enough for ranking; this is NOT the final model.
    model = ExtraTreesClassifier(
        n_estimators=250,
        max_depth=18,
        min_samples_leaf=5,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    )
    model.fit(X, y)

    importance = pd.DataFrame({
        "feature": all_features,
        "importance": model.feature_importances_
    }).sort_values("importance", ascending=False)

    importance["rank"] = range(1, len(importance) + 1)
    importance.to_csv(
        OUT / "tree_feature_importance.csv", index=False
    )

    print("\n[7/8] Security-feature analysis...")
    security = security_analysis(train)
    security.to_csv(
        OUT / "security_feature_analysis.csv", index=False
    )

    engineered_stats = train[
        [c for c in engineered if c in train.columns]
    ].describe().T.reset_index()

    if not engineered_stats.empty:
        engineered_stats = engineered_stats.rename(
            columns={"index": "feature"}
        )
    engineered_stats.to_csv(
        OUT / "engineered_feature_statistics.csv", index=False
    )

    # Select candidate features based on importance.
    # This is a screening list, not the final feature set.
    top_n = min(25, len(importance))
    selected = importance.head(top_n)["feature"].tolist()

    with open(OUT / "phase2_selected_features.txt", "w",
              encoding="utf-8") as f:
        f.write("AI WatchDog - Phase 2 Candidate Features\n")
        f.write("=" * 50 + "\n\n")
        f.write(
            "These are screening candidates from ExtraTrees importance.\n"
        )
        f.write(
            "Do NOT treat this as the final feature set until Phase 3 "
            "validation.\n\n"
        )
        for i, feature in enumerate(selected, 1):
            score = importance.iloc[i - 1]["importance"]
            f.write(f"{i:02d}. {feature}: {score:.8f}\n")

    print("\n[8/8] Generating report...")
    lines = []
    lines.append("AI WatchDog - Phase 2 Feature Engineering Report")
    lines.append("=" * 58)
    lines.append(f"Training rows: {len(train):,}")
    lines.append(f"Candidate numeric features: {len(all_features)}")
    lines.append(f"Engineered features added: {len(engineered)}")
    lines.append("")

    lines.append("TOP 15 FEATURES BY EXTRA-TREES IMPORTANCE")
    lines.append("-" * 45)
    for _, row in importance.head(15).iterrows():
        lines.append(
            f"{row['rank']:2d}. {row['feature']:<35} "
            f"{row['importance']:.6f}"
        )

    lines.append("")
    lines.append("TOP 15 FEATURES BY BENIGN/PHISHING SEPARATION")
    lines.append("-" * 45)
    if not comparison.empty:
        for _, row in comparison.head(15).iterrows():
            lines.append(
                f"{row['feature']:<35} "
                f"std_diff={row['standardized_difference']:.4f}"
            )

    lines.append("")
    lines.append("HIGH CORRELATION PAIRS (|r| >= 0.90)")
    lines.append("-" * 45)
    if pairs_df.empty:
        lines.append("None found.")
    else:
        for _, row in pairs_df.head(20).iterrows():
            lines.append(
                f"{row['feature_1']} <-> {row['feature_2']}: "
                f"{row['correlation']:.4f}"
            )

    lines.append("")
    lines.append("IMPORTANT DATA-SCIENCE RULES")
    lines.append("-" * 45)
    lines.append(
        "1. source is provenance only and must NOT be an ML feature."
    )
    lines.append(
        "2. domain is used for grouping/splitting, not as a raw ML feature."
    )
    lines.append(
        "3. Test and unseen-domain data must not drive feature selection."
    )
    lines.append(
        "4. ExtraTrees importance is a screening tool, not final evidence."
    )
    lines.append(
        "5. Final feature selection happens after Phase 3 validation."
    )
    lines.append(
        "6. Temporal evaluation remains unavailable without reliable timestamps."
    )

    with open(OUT / "phase2_report.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print("\nDONE.")
    print(f"Outputs saved to: {OUT}")
    print("\nTop 15 candidate features:")
    print(importance.head(15).to_string(index=False))

    print("\nNext step:")
    print("Send me data/phase2/phase2_report.txt and")
    print("data/phase2/tree_feature_importance.csv.")
    print("Then we will finalize the Phase-2 feature set before Phase 3 modeling.")


if __name__ == "__main__":
    main()
