import os
import re
import math
import pandas as pd
from urllib.parse import urlparse


# ============================================================
# CONFIGURATION
# ============================================================

DATA_DIR = "datasets"
OUTPUT_DIR = "data"

DATA_FILE = os.path.join(DATA_DIR, "data.csv")
PHISHTANK_FILE = os.path.join(DATA_DIR, "phishtank.csv")
OPENPHISH_FILE = os.path.join(DATA_DIR, "openphish.txt")
TRANCO_FILE = os.path.join(DATA_DIR, "tranco.csv")

MASTER_FILE = os.path.join(OUTPUT_DIR, "phishing_master.csv")
CONFLICT_FILE = os.path.join(OUTPUT_DIR, "label_conflicts.csv")
REPORT_FILE = os.path.join(OUTPUT_DIR, "dataset_report.txt")


# ============================================================
# REQUIRED MASTER COLUMNS
# ============================================================

MASTER_COLUMNS = [
    "url",
    "label",
    "source",
    "domain",
    "tld",
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
    "suspicious_keyword_count"
]


# ============================================================
# SECURITY / PHISHING KEYWORDS
# ============================================================

SUSPICIOUS_KEYWORDS = [
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "authenticate",
    "authentication",
    "account",
    "password",
    "credential",
    "secure",
    "security",
    "update",
    "confirm",
    "confirmation",
    "wallet",
    "bank",
    "payment",
    "billing",
    "invoice",
    "recover",
    "recovery",
    "unlock",
    "suspend",
    "suspended",
    "alert",
    "webscr",
    "validate"
]


SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "rebrand.ly",
    "cutt.ly",
    "shorturl.at",
    "short.me",
    "shortme.id"
}


# ============================================================
# BASIC URL NORMALIZATION
# ============================================================

def normalize_url(url):
    """
    Normalize URL for duplicate detection.

    Does NOT remove meaningful path/query information.
    """

    if pd.isna(url):
        return None

    url = str(url).strip()

    if not url:
        return None

    url = url.replace(" ", "")

    # Lowercase scheme/domain while retaining URL structure.
    url = re.sub(r"^HTTP://", "http://", url, flags=re.I)
    url = re.sub(r"^HTTPS://", "https://", url, flags=re.I)

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url

    try:
        parsed = urlparse(url)

        if not parsed.netloc:
            return None

        scheme = parsed.scheme.lower()
        domain = parsed.hostname

        if not domain:
            return None

        domain = domain.lower()

        # Preserve username/password because @ is a useful feature,
        # but normalize hostname.
        netloc = parsed.netloc

        # Remove default ports.
        netloc = re.sub(r":80$", "", netloc)
        netloc = re.sub(r":443$", "", netloc)

        path = parsed.path.rstrip("/")

        normalized = (
            scheme + "://" +
            netloc.lower() +
            path +
            (("?" + parsed.query) if parsed.query else "")
        )

        return normalized

    except Exception:
        return None


# ============================================================
# DOMAIN EXTRACTION
# ============================================================

def extract_domain(url):

    try:
        parsed = urlparse(url)

        domain = parsed.hostname

        if domain:
            return domain.lower()

    except Exception:
        pass

    return ""


# ============================================================
# ENTROPY
# ============================================================

def calculate_entropy(text):

    if not text:
        return 0.0

    probabilities = []

    for char in set(text):
        probability = text.count(char) / len(text)
        probabilities.append(probability)

    return -sum(
        p * math.log2(p)
        for p in probabilities
        if p > 0
    )


# ============================================================
# IP ADDRESS DETECTION
# ============================================================

def is_ip_address(domain):

    if not domain:
        return 0

    ipv4_pattern = (
        r"^(?:\d{1,3}\.){3}\d{1,3}$"
    )

    if re.match(ipv4_pattern, domain):
        return 1

    return 0


# ============================================================
# URL FEATURE EXTRACTION
# ============================================================

def extract_features(url):

    parsed = urlparse(url)

    domain = parsed.hostname or ""

    domain = domain.lower()

    path = parsed.path or ""

    query = parsed.query or ""

    domain_parts = domain.split(".")

    # Approximate subdomain count.
    #
    # example.com       -> 0
    # www.example.com   -> 1
    # a.b.example.com   -> 2
    #
    # For IP addresses, keep 0.
    if is_ip_address(domain):
        subdomain_count = 0
    else:
        subdomain_count = max(
            len(domain_parts) - 2,
            0
        )

    special_char_count = len(
        re.findall(
            r"[^a-zA-Z0-9]",
            url
        )
    )

    digit_count = len(
        re.findall(
            r"\d",
            url
        )
    )

    suspicious_keyword_count = sum(
        1
        for keyword in SUSPICIOUS_KEYWORDS
        if keyword in url.lower()
    )

    has_shortener = int(
        domain in SHORTENER_DOMAINS
    )

    return {
        "domain": domain,
        "tld": (
            "." + domain_parts[-1]
            if len(domain_parts) >= 2
            else ""
        ),
        "url_length": len(url),
        "domain_length": len(domain),
        "subdomain_count": subdomain_count,
        "path_length": len(path),
        "query_length": len(query),
        "has_ip": is_ip_address(domain),
        "has_https": int(parsed.scheme.lower() == "https"),
        "has_at": int("@" in url),
        "has_dash": int("-" in domain),
        "has_multiple_subdomains": int(
            subdomain_count > 1
        ),
        "special_char_count": special_char_count,
        "digit_count": digit_count,
        "entropy": calculate_entropy(url),
        "has_shortener": has_shortener,
        "suspicious_keyword_count": suspicious_keyword_count
    }


# ============================================================
# LOAD DATA.CSV
# ============================================================

def load_data_csv():

    print("\n[1/4] Loading data.csv...")

    df = pd.read_csv(DATA_FILE)

    # Find URL column
    url_column = next(
        (
            c for c in df.columns
            if c.lower() == "url"
        ),
        None
    )

    # Find label column
    label_column = next(
        (
            c for c in df.columns
            if c.lower() == "label"
        ),
        None
    )

    if url_column is None:
        raise ValueError(
            "data.csv does not contain a URL column."
        )

    if label_column is None:
        raise ValueError(
            "data.csv does not contain a label column."
        )

    result = pd.DataFrame()

    result["url"] = df[url_column]

    result["label"] = (
        df[label_column]
        .astype(str)
        .str.lower()
        .map({
            "good": "benign",
            "bad": "phishing",
            "benign": "benign",
            "phishing": "phishing"
        })
    )

    result["source"] = "data"

    return result


# ============================================================
# LOAD PHISHTANK
# ============================================================

def load_phishtank():

    print("\n[2/4] Loading PhishTank...")

    df = pd.read_csv(PHISHTANK_FILE)

    url_column = next(
        (
            c for c in df.columns
            if c.lower() == "url"
        ),
        None
    )

    if url_column is None:
        raise ValueError(
            "PhishTank file does not contain URL column."
        )

    result = pd.DataFrame()

    result["url"] = df[url_column]

    # PhishTank downloaded dataset is phishing.
    result["label"] = "phishing"

    result["source"] = "phishtank"

    return result


# ============================================================
# LOAD OPENPHISH
# ============================================================

def load_openphish():

    print("\n[3/4] Loading OpenPhish...")

    # OpenPhish community feed is one URL per line.
    df = pd.read_csv(
        OPENPHISH_FILE,
        header=None,
        names=["url"],
        dtype=str
    )

    result = pd.DataFrame()

    result["url"] = df["url"]

    result["label"] = "phishing"

    result["source"] = "openphish"

    return result


# ============================================================
# LOAD TRANCO
# ============================================================

def load_tranco():

    print("\n[4/4] Loading Tranco...")

    # Tranco file normally contains:
    # rank,domain
    #
    # Your file has no header, so explicitly specify names.

    df = pd.read_csv(
        TRANCO_FILE,
        header=None,
        names=["rank", "domain"],
        dtype=str
    )

    # Remove possible header accidentally interpreted as data.
    df = df[
        df["domain"].str.lower() != "domain"
    ]

    domains = (
        df["domain"]
        .dropna()
        .astype(str)
        .str.strip()
    )

    # Convert domain to URL.
    urls = (
        "https://" +
        domains
    )

    result = pd.DataFrame()

    result["url"] = urls

    result["label"] = "benign"

    result["source"] = "tranco"

    return result


# ============================================================
# CLEAN DATA
# ============================================================

def clean_dataset(df):

    print("\nCleaning URLs...")

    original_count = len(df)

    # Remove missing URLs.
    df = df.dropna(
        subset=["url"]
    ).copy()

    # Normalize URL.
    df["normalized_url"] = (
        df["url"]
        .map(normalize_url)
    )

    # Remove invalid URLs.
    df = df.dropna(
        subset=["normalized_url"]
    )

    # Use normalized URL as final URL.
    df["url"] = df["normalized_url"]

    df.drop(
        columns=["normalized_url"],
        inplace=True
    )

    # Normalize labels.
    df["label"] = (
        df["label"]
        .astype(str)
        .str.lower()
        .str.strip()
    )

    df = df[
        df["label"].isin([
            "benign",
            "phishing"
        ])
    ]

    print(
        f"Rows before cleaning : {original_count:,}"
    )

    print(
        f"Rows after cleaning  : {len(df):,}"
    )

    return df


# ============================================================
# FIND LABEL CONFLICTS
# ============================================================

def find_conflicts(df):

    print("\nChecking label conflicts...")

    grouped = (
        df.groupby("url")["label"]
        .agg(lambda x: sorted(set(x)))
    )

    conflicts = grouped[
        grouped.map(len) > 1
    ]

    if len(conflicts) == 0:

        print("No conflicting URL labels found.")

        return pd.DataFrame(
            columns=[
                "url",
                "labels"
            ]
        )

    conflict_df = pd.DataFrame({
        "url": conflicts.index,
        "labels": conflicts.map(
            lambda x: "|".join(x)
        ).values
    })

    print(
        f"Conflicting URLs: {len(conflict_df):,}"
    )

    return conflict_df


# ============================================================
# DEDUPLICATION
# ============================================================

def deduplicate(df):

    print("\nDeduplicating...")

    before = len(df)

    # Source priority:
    #
    # PhishTank > OpenPhish > data > Tranco
    #
    # If a URL appears as phishing in a threat-intelligence
    # source and benign in Tranco, keep the phishing record.

    source_priority = {
        "phishtank": 4,
        "openphish": 3,
        "data": 2,
        "tranco": 1
    }

    df["priority"] = (
        df["source"]
        .map(source_priority)
        .fillna(0)
    )

    df = df.sort_values(
        by=["url", "priority"],
        ascending=[True, False]
    )

    df = df.drop_duplicates(
        subset=["url"],
        keep="first"
    )

    df = df.drop(
        columns=["priority"]
    )

    after = len(df)

    print(
        f"Before deduplication : {before:,}"
    )

    print(
        f"After deduplication  : {after:,}"
    )

    print(
        f"Duplicates removed    : {before-after:,}"
    )

    return df


# ============================================================
# FEATURE ENGINEERING
# ============================================================

def generate_features(df):

    print("\nExtracting URL features...")

    feature_rows = []

    for i, url in enumerate(
        df["url"],
        start=1
    ):

        if i % 100000 == 0:
            print(
                f"Processed {i:,} URLs..."
            )

        try:
            feature_rows.append(
                extract_features(url)
            )

        except Exception:
            feature_rows.append({
                key: 0
                for key in MASTER_COLUMNS[3:]
            })

    features = pd.DataFrame(
        feature_rows
    )

    df = pd.concat(
        [
            df.reset_index(drop=True),
            features.reset_index(drop=True)
        ],
        axis=1
    )

    return df


# ============================================================
# CREATE REPORT
# ============================================================

def create_report(
    original,
    cleaned,
    conflicts,
    master
):

    print("\nCreating dataset report...")

    lines = []

    lines.append(
        "AI WatchDog - Master Dataset Report"
    )

    lines.append(
        "=" * 50
    )

    lines.append("")

    lines.append(
        f"Combined rows before cleaning: "
        f"{len(original):,}"
    )

    lines.append(
        f"Rows after cleaning: "
        f"{len(cleaned):,}"
    )

    lines.append(
        f"Final master rows: "
        f"{len(master):,}"
    )

    lines.append(
        f"Label conflicts: "
        f"{len(conflicts):,}"
    )

    lines.append("")

    lines.append(
        "LABEL DISTRIBUTION"
    )

    lines.append(
        "-" * 30
    )

    label_counts = (
        master["label"]
        .value_counts()
    )

    for label, count in label_counts.items():

        percentage = (
            count /
            len(master) *
            100
        )

        lines.append(
            f"{label}: "
            f"{count:,} "
            f"({percentage:.2f}%)"
        )

    lines.append("")

    lines.append(
        "SOURCE DISTRIBUTION"
    )

    lines.append(
        "-" * 30
    )

    source_counts = (
        master["source"]
        .value_counts()
    )

    for source, count in source_counts.items():

        lines.append(
            f"{source}: {count:,}"
        )

    lines.append("")

    lines.append(
        "FEATURES"
    )

    lines.append(
        "-" * 30
    )

    for column in MASTER_COLUMNS:
        lines.append(column)

    with open(
        REPORT_FILE,
        "w",
        encoding="utf-8"
    ) as f:

        f.write(
            "\n".join(lines)
        )


# ============================================================
# MAIN PIPELINE
# ============================================================

def main():

    print(
        "\n=========================================="
    )

    print(
        " AI WATCHDOG MASTER DATASET BUILDER"
    )

    print(
        "=========================================="
    )

    os.makedirs(
        OUTPUT_DIR,
        exist_ok=True
    )

    # --------------------------------------------------------
    # LOAD ALL SOURCES
    # --------------------------------------------------------

    datasets = []

    datasets.append(
        load_data_csv()
    )

    datasets.append(
        load_phishtank()
    )

    datasets.append(
        load_openphish()
    )

    datasets.append(
        load_tranco()
    )

    combined = pd.concat(
        datasets,
        ignore_index=True
    )

    print(
        "\nCombined dataset:",
        f"{len(combined):,}",
        "rows"
    )

    # --------------------------------------------------------
    # CLEAN
    # --------------------------------------------------------

    cleaned = clean_dataset(
        combined
    )

    # --------------------------------------------------------
    # CONFLICT CHECK
    # --------------------------------------------------------

    conflicts = find_conflicts(
        cleaned
    )

    conflicts.to_csv(
        CONFLICT_FILE,
        index=False
    )

    # --------------------------------------------------------
    # DEDUPLICATE
    # --------------------------------------------------------

    master = deduplicate(
        cleaned
    )

    # --------------------------------------------------------
    # FEATURE ENGINEERING
    # --------------------------------------------------------

    master = generate_features(
        master
    )

    # --------------------------------------------------------
    # FINAL COLUMN ORDER
    # --------------------------------------------------------

    master = master[
        MASTER_COLUMNS
    ]

    # --------------------------------------------------------
    # SAVE MASTER DATASET
    # --------------------------------------------------------

    master.to_csv(
        MASTER_FILE,
        index=False
    )

    # --------------------------------------------------------
    # REPORT
    # --------------------------------------------------------

    create_report(
        combined,
        cleaned,
        conflicts,
        master
    )

    # --------------------------------------------------------
    # FINAL SUMMARY
    # --------------------------------------------------------

    print(
        "\n=========================================="
    )

    print(
        " MASTER DATASET CREATED"
    )

    print(
        "=========================================="
    )

    print(
        f"File: {MASTER_FILE}"
    )

    print(
        f"Rows: {len(master):,}"
    )

    print(
        f"Columns: {len(master.columns)}"
    )

    print("\nLabels:")

    print(
        master["label"]
        .value_counts()
        .to_string()
    )

    print("\nSources:")

    print(
        master["source"]
        .value_counts()
        .to_string()
    )

    print(
        "\nNext step: perform EDA and dataset-quality checks."
    )


if __name__ == "__main__":
    main()