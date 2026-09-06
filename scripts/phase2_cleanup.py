"""
AI WatchDog - Phase 2 CLEANUP
=============================

Purpose:
- Remove redundant / duplicate engineered features.
- Keep one interpretable feature when multiple features measure the same thing.
- Apply EXACTLY the same feature set to train/validation/test/unseen-domain.
- Never use label, source, domain, or raw URL as ML predictors.
- Keep the original master dataset untouched.

Input:
    data/splits/train.csv
    data/splits/validation.csv
    data/splits/test.csv
    data/splits/unseen_domain_test.csv
    data/phase2/tree_feature_importance.csv

Output:
    data/phase2_clean/
        train.csv
        validation.csv
        test.csv
        unseen_domain_test.csv
        selected_features.txt
        removed_features.txt
        cleanup_report.txt

Run:
    python phase2_cleanup.py
"""

from pathlib import Path
import pandas as pd
import numpy as np

BASE = Path("data")
SPLITS = BASE / "splits"
PHASE2 = BASE / "phase2"
OUT = BASE / "phase2_clean"
OUT.mkdir(parents=True, exist_ok=True)

FILES = {
    "train": SPLITS / "train.csv",
    "validation": SPLITS / "validation.csv",
    "test": SPLITS / "test.csv",
    "unseen_domain_test": SPLITS / "unseen_domain_test.csv",
}

IMPORTANCE_FILE = PHASE2 / "tree_feature_importance.csv"

# These are identifiers / metadata, NOT ML predictors.
NON_FEATURES = {
    "url",
    "label",
    "source",
    "domain",
    "tld",
}

# ============================================================
# REDUNDANCY POLICY
# ============================================================
#
# When two features measure almost exactly the same thing,
# prefer the simpler/original feature.
#
# This is a conservative cleanup. We are NOT trying to reduce
# the feature count as much as possible.
#
# The model can still receive ~20-30 useful features.
# ============================================================

PREFERRED_FEATURES = [
    # Original core URL features
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

    # Useful engineered structural features
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

# Explicit redundant features identified in Phase 2.
# These are removed because another retained feature already
# represents the same information.
KNOWN_REDUNDANT = {
    "url_special_count",       # same as special_char_count
    "url_digit_count",         # same as digit_count
    "letter_count",            # strongly tied to URL length
    "lowercase_count",         # strongly tied to letter count/URL length
    "domain_dot_count",        # strongly tied to subdomain_count
    "at_count",                # duplicate/near duplicate of has_at
    "equals_count",            # strongly tied to query parameters
    "ampersand_count",         # strongly tied to query parameters
}


def fail_if_missing():
    missing = [str(p) for p in FILES.values() if not p.exists()]
    if missing:
        raise FileNotFoundError(
            "Missing Phase 1.5 split files:\n" + "\n".join(missing)
        )

    if not IMPORTANCE_FILE.exists():
        raise FileNotFoundError(
            f"Missing {IMPORTANCE_FILE}.\n"
            "Run phase2_feature_analysis.py first."
        )


def load_importance():
    imp = pd.read_csv(IMPORTANCE_FILE)

    required = {"feature", "importance"}
    if not required.issubset(imp.columns):
        raise ValueError(
            f"{IMPORTANCE_FILE} must contain: {required}"
        )

    return imp.sort_values("importance", ascending=False)


def choose_features(train):
    """
    Build a conservative, interpretable feature set.

    Strategy:
    1. Start with preferred features that actually exist.
    2. Never include known redundant features.
    3. Optionally add a few additional high-importance features
       only if they are not highly correlated with selected ones.
    """

    numeric = [
        c for c in train.columns
        if c not in NON_FEATURES
        and pd.api.types.is_numeric_dtype(train[c])
    ]

    selected = [
        f for f in PREFERRED_FEATURES
        if f in numeric and f not in KNOWN_REDUNDANT
    ]

    importance = load_importance()

    # Candidate additions not already selected.
    candidates = [
        f for f in importance["feature"].tolist()
        if f in numeric
        and f not in selected
        and f not in KNOWN_REDUNDANT
    ]

    # Use train-only correlations.
    corr = train[numeric].corr(numeric_only=True)

    # Add a candidate only if it is not extremely redundant
    # with a feature already selected.
    for feature in candidates:
        if len(selected) >= 30:
            break

        if feature not in corr.columns:
            continue

        too_correlated = False

        for kept in selected:
            if kept in corr.columns:
                value = corr.loc[feature, kept]
                if pd.notna(value) and abs(value) >= 0.95:
                    too_correlated = True
                    break

        if not too_correlated:
            selected.append(feature)

    return selected, corr


def make_clean_file(path, features, name):
    df = pd.read_csv(path)

    missing = [f for f in features if f not in df.columns]
    if missing:
        raise ValueError(
            f"{name}: missing selected features: {missing}"
        )

    # Keep identifiers needed for analysis/evaluation,
    # followed by the final ML feature set.
    columns = ["url", "label", "source", "domain", "tld"] + features
    columns = [c for c in columns if c in df.columns]

    clean = df[columns].copy()

    # Convert feature columns to numeric safely.
    for f in features:
        clean[f] = pd.to_numeric(
            clean[f], errors="coerce"
        ).replace(
            [np.inf, -np.inf], np.nan
        ).fillna(0)

    output = OUT / f"{name}.csv"
    clean.to_csv(output, index=False)

    return clean


def main():
    print("=" * 68)
    print("AI WATCHDOG - PHASE 2 FEATURE CLEANUP")
    print("=" * 68)

    fail_if_missing()

    print("\n[1/5] Loading training data...")
    train = pd.read_csv(FILES["train"])
    print(f"Training rows: {len(train):,}")

    print("\n[2/5] Selecting non-redundant features...")
    selected, corr = choose_features(train)

    # Final safety check: no metadata/raw fields.
    selected = [
        f for f in selected
        if f not in NON_FEATURES
    ]

    print(f"Final candidate feature count: {len(selected)}")

    print("\nSelected features:")
    for i, f in enumerate(selected, 1):
        print(f"{i:02d}. {f}")

    print("\n[3/5] Writing cleaned datasets...")

    cleaned = {}
    for name, path in FILES.items():
        cleaned[name] = make_clean_file(
            path, selected, name
        )
        print(
            f"{name:20s}: "
            f"{len(cleaned[name]):,} rows"
        )

    print("\n[4/5] Writing feature lists...")

    # Features removed from numeric candidates.
    all_numeric = [
        c for c in train.columns
        if c not in NON_FEATURES
        and pd.api.types.is_numeric_dtype(train[c])
    ]

    removed = [
        f for f in all_numeric
        if f not in selected
    ]

    with open(OUT / "selected_features.txt", "w",
              encoding="utf-8") as f:
        f.write("AI WatchDog - Final Phase 2 Candidate Features\n")
        f.write("=" * 55 + "\n\n")
        f.write(
            "These features are candidates for Phase 3 model "
            "experiments.\n"
        )
        f.write(
            "Final selection must still be validated using "
            "validation performance.\n\n"
        )

        for i, feature in enumerate(selected, 1):
            f.write(f"{i:02d}. {feature}\n")

    with open(OUT / "removed_features.txt", "w",
              encoding="utf-8") as f:
        f.write("AI WatchDog - Removed / Redundant Features\n")
        f.write("=" * 50 + "\n\n")

        for feature in removed:
            reason = (
                "known redundant feature"
                if feature in KNOWN_REDUNDANT
                else "not selected after correlation/importance screening"
            )
            f.write(f"{feature}: {reason}\n")

    print("\n[5/5] Generating cleanup report...")

    report = []
    report.append("AI WatchDog - Phase 2 Cleanup Report")
    report.append("=" * 55)
    report.append("")
    report.append(f"Original candidate numeric features: {len(all_numeric)}")
    report.append(f"Final candidate features: {len(selected)}")
    report.append(f"Removed features: {len(removed)}")
    report.append("")

    report.append("FINAL FEATURE SET")
    report.append("-" * 30)
    for i, feature in enumerate(selected, 1):
        report.append(f"{i:02d}. {feature}")

    report.append("")
    report.append("REMOVED FEATURES")
    report.append("-" * 30)
    for feature in removed:
        if feature in KNOWN_REDUNDANT:
            report.append(
                f"{feature} -> redundant / duplicate representation"
            )
        else:
            report.append(
                f"{feature} -> excluded by correlation/importance screening"
            )

    report.append("")
    report.append("DATA-SCIENCE SAFETY")
    report.append("-" * 30)
    report.append(
        "source, domain, url, and tld are retained only as metadata."
    )
    report.append(
        "They are NOT part of the ML feature matrix."
    )
    report.append(
        "Feature-selection correlation was calculated on TRAIN only."
    )
    report.append(
        "The same final feature list is applied to every split."
    )
    report.append(
        "Original master.csv and Phase 1.5 split files are untouched."
    )

    report.append("")
    report.append("SPLIT SIZES")
    report.append("-" * 30)
    for name, df in cleaned.items():
        report.append(
            f"{name}: {len(df):,} rows"
        )

    report.append("")
    report.append(
        "NEXT STEP: Phase 3 baseline model training."
    )

    (OUT / "cleanup_report.txt").write_text(
        "\n".join(report),
        encoding="utf-8"
    )

    print("\n" + "=" * 68)
    print("PHASE 2 CLEANUP COMPLETE")
    print("=" * 68)
    print(f"Output directory: {OUT}")
    print("\nUse phase2_clean/*.csv for Phase 3.")
    print("Do NOT overwrite the original master dataset.")


if __name__ == "__main__":
    main()
