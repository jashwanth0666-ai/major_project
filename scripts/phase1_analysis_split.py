"""
AI WatchDog - Phase 1.5
Automates:
1. Data-quality analysis
2. Label/source distribution
3. Numeric feature statistics
4. TLD/security-feature analysis
5. Domain-label conflict analysis
6. Domain-aware train/validation/test split
7. True unseen-domain holdout
8. Report generation

Expected input:
    data/phishing_master.csv

If your master file is elsewhere, change MASTER_FILE below.
"""

from pathlib import Path
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split

# ============================================================
# CONFIG
# ============================================================

MASTER_FILE = Path("data/phishing_master.csv")
OUTPUT_ROOT = Path("data")
ANALYSIS_DIR = OUTPUT_ROOT / "analysis"
SPLIT_DIR = OUTPUT_ROOT / "splits"

RANDOM_STATE = 42
UNSEEN_DOMAIN_FRACTION = 0.10

REQUIRED_COLUMNS = [
    "url", "label", "source", "domain", "tld",
    "url_length", "domain_length", "subdomain_count",
    "path_length", "query_length", "has_ip", "has_https",
    "has_at", "has_dash", "has_multiple_subdomains",
    "special_char_count", "digit_count", "entropy",
    "has_shortener", "suspicious_keyword_count"
]

# ============================================================
# HELPERS
# ============================================================

def find_master_file():
    """Find master CSV using the expected path plus common alternatives."""
    candidates = [
        MASTER_FILE,
        Path("phishing_master.csv"),
        Path("master.csv"),
        Path("data/master.csv"),
    ]

    for path in candidates:
        if path.exists():
            return path

    raise FileNotFoundError(
        "\nCould not find phishing_master.csv.\n"
        "Put it here:\n"
        "    data/phishing_master.csv\n"
        "or change MASTER_FILE at the top of this script."
    )


def save_csv(df, path):
    path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(path, index=False)


def print_section(title):
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)


# ============================================================
# MAIN
# ============================================================

def main():

    ANALYSIS_DIR.mkdir(parents=True, exist_ok=True)
    SPLIT_DIR.mkdir(parents=True, exist_ok=True)

    print_section("AI WATCHDOG - PHASE 1.5 DATA ANALYSIS")

    # --------------------------------------------------------
    # 1. LOAD
    # --------------------------------------------------------

    master_path = find_master_file()

    print(f"Master file: {master_path}")

    df = pd.read_csv(master_path)

    print(f"Rows    : {len(df):,}")
    print(f"Columns : {len(df.columns)}")

    # --------------------------------------------------------
    # 2. SCHEMA VALIDATION
    # --------------------------------------------------------

    print_section("[1/7] SCHEMA VALIDATION")

    missing_columns = [
        c for c in REQUIRED_COLUMNS
        if c not in df.columns
    ]

    extra_columns = [
        c for c in df.columns
        if c not in REQUIRED_COLUMNS
    ]

    if missing_columns:
        print("ERROR - Missing columns:")
        for c in missing_columns:
            print("  -", c)
        raise ValueError("Master dataset schema is incomplete.")

    print("All 20 required columns are present.")

    if extra_columns:
        print("Extra columns:", extra_columns)

    # --------------------------------------------------------
    # 3. DATA QUALITY
    # --------------------------------------------------------

    print_section("[2/7] DATA QUALITY")

    quality = []

    for col in df.columns:
        quality.append({
            "column": col,
            "dtype": str(df[col].dtype),
            "missing": int(df[col].isna().sum()),
            "missing_pct": round(
                df[col].isna().mean() * 100, 4
            ),
            "unique": int(df[col].nunique(dropna=True))
        })

    quality_df = pd.DataFrame(quality)

    save_csv(
        quality_df,
        ANALYSIS_DIR / "data_quality.csv"
    )

    print("\nMissing values:")
    print(
        quality_df[
            ["column", "missing", "missing_pct"]
        ].to_string(index=False)
    )

    duplicate_urls = int(df["url"].duplicated().sum())

    print(f"\nDuplicate URLs: {duplicate_urls:,}")

    # --------------------------------------------------------
    # 4. DISTRIBUTIONS + FEATURE STATISTICS
    # --------------------------------------------------------

    print_section("[3/7] LABEL / SOURCE / FEATURE ANALYSIS")

    label_counts = df["label"].value_counts(dropna=False)
    source_counts = df["source"].value_counts(dropna=False)

    print("\nLABEL DISTRIBUTION")
    print(label_counts)

    label_df = label_counts.rename(
        "count"
    ).reset_index()

    label_df.columns = ["label", "count"]

    label_df["percentage"] = (
        label_df["count"] / len(df) * 100
    ).round(3)

    save_csv(
        label_df,
        ANALYSIS_DIR / "label_distribution.csv"
    )

    print("\nSOURCE DISTRIBUTION")
    print(source_counts)

    source_df = source_counts.rename(
        "count"
    ).reset_index()

    source_df.columns = ["source", "count"]

    source_df["percentage"] = (
        source_df["count"] / len(df) * 100
    ).round(3)

    save_csv(
        source_df,
        ANALYSIS_DIR / "source_distribution.csv"
    )

    numeric_cols = df.select_dtypes(
        include=np.number
    ).columns.tolist()

    stats = df[numeric_cols].describe().T

    stats["missing"] = (
        df[numeric_cols].isna().sum()
    )

    save_csv(
        stats.reset_index().rename(
            columns={"index": "feature"}
        ),
        ANALYSIS_DIR / "numeric_feature_statistics.csv"
    )

    print("\nNumeric feature statistics saved.")

    # --------------------------------------------------------
    # 5. TLD + SECURITY FEATURES
    # --------------------------------------------------------

    print_section("[4/7] TLD / SECURITY ANALYSIS")

    tld_counts = (
        df["tld"]
        .fillna("")
        .value_counts()
        .head(50)
        .rename("count")
        .reset_index()
    )

    tld_counts.columns = ["tld", "count"]

    save_csv(
        tld_counts,
        ANALYSIS_DIR / "top_tlds.csv"
    )

    security_columns = [
        "has_ip",
        "has_https",
        "has_at",
        "has_dash",
        "has_multiple_subdomains",
        "has_shortener"
    ]

    security_rows = []

    for col in security_columns:
        counts = df[col].value_counts(dropna=False)

        security_rows.append({
            "feature": col,
            "zero": int(counts.get(0, 0)),
            "one": int(counts.get(1, 0)),
            "percentage_one": round(
                pd.to_numeric(
                    df[col],
                    errors="coerce"
                ).mean() * 100,
                3
            )
        })

    security_df = pd.DataFrame(security_rows)

    save_csv(
        security_df,
        ANALYSIS_DIR / "security_features.csv"
    )

    print(security_df.to_string(index=False))

    # --------------------------------------------------------
    # 6. DOMAIN LABEL CONFLICTS
    # --------------------------------------------------------

    print_section("[5/7] DOMAIN LABEL CONFLICT ANALYSIS")

    domain_label_counts = (
        df.dropna(subset=["domain"])
        .groupby("domain")["label"]
        .nunique()
    )

    conflicting_domains = domain_label_counts[
        domain_label_counts > 1
    ]

    conflict_df = (
        df[
            df["domain"].isin(
                conflicting_domains.index
            )
        ][
            ["url", "domain", "label", "source"]
        ]
        .sort_values(["domain", "label"])
    )

    save_csv(
        conflict_df,
        ANALYSIS_DIR / "domain_label_conflicts.csv"
    )

    print(
        "Domains containing both benign and phishing labels:",
        f"{len(conflicting_domains):,}"
    )

    # --------------------------------------------------------
    # 7. TRUE UNSEEN-DOMAIN HOLDOUT + DOMAIN-AWARE SPLITS
    # --------------------------------------------------------

    print_section("[6/7] DOMAIN-AWARE DATA SPLITTING")

    # IMPORTANT:
    # First reserve unseen domains.
    # Only the remaining domains can participate in
    # train/validation/test.
    #
    # This prevents the unseen-domain test from sharing
    # domains with train/validation/test.

    domains = (
        df["domain"]
        .dropna()
        .astype(str)
        .unique()
    )

    if len(domains) < 10:
        raise ValueError(
            "Too few unique domains for domain-aware splitting."
        )

    development_domains, unseen_domains = train_test_split(
        domains,
        test_size=UNSEEN_DOMAIN_FRACTION,
        random_state=RANDOM_STATE
    )

    train_domains, temp_domains = train_test_split(
        development_domains,
        test_size=0.2222222222,  # gives 70/10/10 overall
        random_state=RANDOM_STATE
    )

    validation_domains, test_domains = train_test_split(
        temp_domains,
        test_size=0.50,
        random_state=RANDOM_STATE
    )

    train = df[
        df["domain"].isin(train_domains)
    ].copy()

    validation = df[
        df["domain"].isin(validation_domains)
    ].copy()

    test = df[
        df["domain"].isin(test_domains)
    ].copy()

    unseen_domain_test = df[
        df["domain"].isin(unseen_domains)
    ].copy()

    splits = {
        "train": train,
        "validation": validation,
        "test": test,
        "unseen_domain_test": unseen_domain_test
    }

    for name, split_df in splits.items():
        save_csv(
            split_df,
            SPLIT_DIR / f"{name}.csv"
        )

    print(f"Train              : {len(train):,}")
    print(f"Validation         : {len(validation):,}")
    print(f"Test               : {len(test):,}")
    print(f"Unseen-domain test : {len(unseen_domain_test):,}")

    # --------------------------------------------------------
    # DOMAIN OVERLAP VERIFICATION
    # --------------------------------------------------------

    domain_sets = {
        name: set(split["domain"].dropna())
        for name, split in splits.items()
    }

    print("\nDOMAIN OVERLAP CHECK")

    names = list(domain_sets.keys())

    overlap_rows = []

    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            a = names[i]
            b = names[j]

            overlap = len(
                domain_sets[a] &
                domain_sets[b]
            )

            overlap_rows.append({
                "split_a": a,
                "split_b": b,
                "shared_domains": overlap
            })

            print(
                f"{a} <-> {b}: {overlap}"
            )

    overlap_df = pd.DataFrame(overlap_rows)

    save_csv(
        overlap_df,
        ANALYSIS_DIR / "split_domain_overlap.csv"
    )

    # --------------------------------------------------------
    # SPLIT LABEL DISTRIBUTION
    # --------------------------------------------------------

    split_label_rows = []

    for name, split_df in splits.items():

        counts = split_df["label"].value_counts()

        for label, count in counts.items():

            split_label_rows.append({
                "split": name,
                "label": label,
                "count": int(count),
                "percentage": round(
                    count / len(split_df) * 100,
                    3
                )
            })

    split_label_df = pd.DataFrame(
        split_label_rows
    )

    save_csv(
        split_label_df,
        ANALYSIS_DIR / "split_label_distribution.csv"
    )

    # --------------------------------------------------------
    # FINAL REPORT
    # --------------------------------------------------------

    print_section("[7/7] GENERATING FINAL REPORT")

    report = []

    report.append(
        "AI WatchDog - Phase 1.5 Dataset Analysis Report"
    )
    report.append("=" * 60)
    report.append("")
    report.append(f"Master rows: {len(df):,}")
    report.append(f"Master columns: {len(df.columns)}")
    report.append(f"Duplicate URLs: {duplicate_urls:,}")
    report.append(
        f"Conflicting-label domains: "
        f"{len(conflicting_domains):,}"
    )
    report.append("")

    report.append("LABEL DISTRIBUTION")
    report.append("-" * 30)

    for _, row in label_df.iterrows():
        report.append(
            f"{row['label']}: "
            f"{int(row['count']):,} "
            f"({row['percentage']:.2f}%)"
        )

    report.append("")
    report.append("SOURCE DISTRIBUTION")
    report.append("-" * 30)

    for _, row in source_df.iterrows():
        report.append(
            f"{row['source']}: "
            f"{int(row['count']):,} "
            f"({row['percentage']:.2f}%)"
        )

    report.append("")
    report.append("DOMAIN-AWARE SPLITS")
    report.append("-" * 30)

    for name, split_df in splits.items():
        report.append(
            f"{name}: {len(split_df):,} rows, "
            f"{split_df['domain'].nunique():,} domains"
        )

    report.append("")
    report.append(
        "Temporal test was NOT generated because the current "
        "master schema contains no timestamp/date column."
    )
    report.append(
        "Create temporal_test.csv later from a source containing "
        "reliable collection/submission timestamps."
    )

    report.append("")
    report.append("OUTPUT FILES")
    report.append("-" * 30)

    for path in sorted(ANALYSIS_DIR.glob("*.csv")):
        report.append(str(path))

    report.append(str(ANALYSIS_DIR / "phase1_analysis_report.txt"))

    for path in sorted(SPLIT_DIR.glob("*.csv")):
        report.append(str(path))

    report_path = (
        ANALYSIS_DIR /
        "phase1_analysis_report.txt"
    )

    report_path.write_text(
        "\n".join(report),
        encoding="utf-8"
    )

    print("\n" + "=" * 70)
    print("PHASE 1.5 COMPLETE")
    print("=" * 70)

    print("\nAnalysis files:")
    print(f"  {ANALYSIS_DIR}")

    print("\nSplit files:")
    print(f"  {SPLIT_DIR}")

    print("\nIMPORTANT:")
    print(
        "Temporal test is not created because your current "
        "20-column master dataset has no timestamp."
    )

    print(
        "\nNext: inspect phase1_analysis_report.txt and "
        "then proceed to Phase 2 feature engineering."
    )


if __name__ == "__main__":
    main()
