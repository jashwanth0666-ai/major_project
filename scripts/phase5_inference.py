"""
AI WatchDog - PHASE 5
Production Inference + Risk Engine + Explainability

Purpose:
    Load the Phase 4 calibrated XGBoost artifact and provide reusable
    single-URL and batch inference without retraining.

Expected Phase 4 artifact:
    data/phase4/xgboost_calibrated.joblib

Run:
    python phase5_inference.py "https://example.com/login"

Batch:
    python phase5_inference.py --batch data/splits/test.csv --output data/phase5/predictions.csv

The model expects the exact 25 features selected in Phase 2/Phase 4.
"""

from __future__ import annotations

import argparse
import json
import math
import re
from pathlib import Path
from urllib.parse import urlparse

import joblib
import numpy as np
import pandas as pd


# ---------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "data" / "phase4" / "xgboost_calibrated.joblib"
DEFAULT_OUTPUT = BASE_DIR / "data" / "phase5" / "predictions.csv"

THRESHOLD = 0.15

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

SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "rb.gy",
    "shorturl.at",
    "rebrand.ly",
    "tiny.cc",
}

SUSPICIOUS_KEYWORDS = {
    "login",
    "signin",
    "verify",
    "verification",
    "account",
    "secure",
    "security",
    "update",
    "confirm",
    "password",
    "credential",
    "bank",
    "payment",
    "invoice",
    "wallet",
    "paypal",
    "webscr",
    "authenticate",
    "auth",
    "recover",
    "unlock",
    "suspended",
    "bonus",
    "free",
    "claim",
    "gift",
}

IPV4_RE = re.compile(
    r"^(?:\d{1,3}\.){3}\d{1,3}$"
)


# ---------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------

def safe_entropy(text: str) -> float:
    """Shannon entropy of a string."""
    if not text:
        return 0.0

    counts = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1

    n = len(text)
    return float(
        -sum((count / n) * math.log2(count / n)
             for count in counts.values())
    )


def normalize_url(url: str) -> str:
    """Normalize only enough to make URL parsing reliable."""
    url = str(url).strip()

    if not url:
        raise ValueError("URL is empty.")

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url

    return url


def extract_features(url: str) -> dict:
    """
    Reproduce the 25 Phase 4 features.

    This function intentionally uses only URL-derived information.
    No DNS, WHOIS, webpage content, or external network request is made.
    """
    url = normalize_url(url)
    parsed = urlparse(url)

    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""

    # Preserve the original URL text for character-level features.
    raw = url

    labels = [x for x in hostname.split(".") if x]

    # For a normal domain:
    # example.com -> 0 subdomains
    # login.example.com -> 1 subdomain
    # a.b.example.com -> 2 subdomains
    subdomain_count = max(len(labels) - 2, 0)

    has_ip = int(bool(IPV4_RE.fullmatch(hostname)))

    # URL path segments, excluding empty components.
    path_segment_count = len(
        [segment for segment in path.split("/") if segment]
    )

    query_parameter_count = (
        len([x for x in query.split("&") if x])
        if query
        else 0
    )

    digits = sum(ch.isdigit() for ch in raw)
    uppercase = sum(ch.isupper() for ch in raw)
    letters = sum(ch.isalpha() for ch in raw)
    special = sum(not ch.isalnum() for ch in raw)

    digit_ratio = digits / len(raw) if raw else 0.0

    suspicious_keyword_count = sum(
        1
        for keyword in SUSPICIOUS_KEYWORDS
        if keyword in raw.lower()
    )

    has_shortener = int(
        hostname in SHORTENER_DOMAINS
        or any(hostname.endswith("." + d) for d in SHORTENER_DOMAINS)
    )

    percent_encoded_count = len(re.findall(r"%[0-9A-Fa-f]{2}", raw))

    features = {
        "url_length": len(raw),
        "domain_length": len(hostname),
        "subdomain_count": subdomain_count,
        "path_length": len(path),
        "query_length": len(query),
        "has_ip": has_ip,
        "has_https": int(parsed.scheme.lower() == "https"),
        "has_at": int("@" in raw),
        "has_dash": int("-" in raw),
        "has_multiple_subdomains": int(subdomain_count >= 2),
        "special_char_count": special,
        "digit_count": digits,
        "entropy": safe_entropy(raw),
        "has_shortener": has_shortener,
        "suspicious_keyword_count": suspicious_keyword_count,
        "dot_count": raw.count("."),
        "slash_count": raw.count("/"),
        "hyphen_count": raw.count("-"),
        "percent_encoded_count": percent_encoded_count,
        "query_parameter_count": query_parameter_count,
        "uppercase_count": uppercase,
        "domain_digit_count": sum(ch.isdigit() for ch in hostname),
        "domain_entropy": safe_entropy(hostname),
        "path_segment_count": path_segment_count,
        "digit_ratio": digit_ratio,
    }

    return features


# ---------------------------------------------------------------------
# Explainability
# ---------------------------------------------------------------------

def generate_reasons(url: str, features: dict) -> list[str]:
    """
    Generate human-readable URL-level warning reasons.

    These are rule-based explanations of observed URL characteristics.
    They are NOT claims about individual model feature contributions.
    """
    reasons = []

    if features["has_ip"]:
        reasons.append("IP address used instead of a normal domain")

    if features["has_at"]:
        reasons.append("URL contains '@'")

    if features["has_shortener"]:
        reasons.append("URL uses a known URL-shortening service")

    if features["suspicious_keyword_count"] > 0:
        reasons.append("Suspicious security/account-related keyword detected")

    if features["has_multiple_subdomains"] and not features["has_ip"]:
        reasons.append("Multiple subdomains detected")

    if features["has_dash"]:
        reasons.append("Hyphenated domain/URL structure detected")

    if features["percent_encoded_count"] > 0:
        reasons.append("Percent-encoded characters detected")

    if features["digit_ratio"] >= 0.25:
        reasons.append("High proportion of digits in URL")

    if features["url_length"] >= 100:
        reasons.append("Unusually long URL")

    if features["domain_length"] >= 40:
        reasons.append("Unusually long domain")

    if features["query_parameter_count"] >= 4:
        reasons.append("Many query parameters detected")

    if features["subdomain_count"] >= 3:
        reasons.append("Deep subdomain structure detected")

    if not reasons:
        reasons.append("No major URL-level warning indicators detected")

    return reasons


def risk_level(risk_score: int) -> str:
    if risk_score <= 25:
        return "SAFE"
    if risk_score <= 50:
        return "LOW RISK"
    if risk_score <= 75:
        return "SUSPICIOUS"
    return "HIGH RISK"


# ---------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------

class WatchDogDetector:
    """Reusable AI WatchDog inference engine."""

    def __init__(self, model_path: Path = MODEL_PATH):
        self.model_path = Path(model_path)

        if not self.model_path.exists():
            raise FileNotFoundError(
                f"Phase 4 model artifact not found:\n"
                f"  {self.model_path}\n\n"
                f"Run Phase 4 first and make sure "
                f"'xgboost_calibrated.joblib' exists."
            )

        self.model = joblib.load(self.model_path)

    def predict(self, url: str) -> dict:
        features = extract_features(url)

        X = pd.DataFrame(
            [[features[f] for f in FEATURES]],
            columns=FEATURES,
        )

        probability = float(self.model.predict_proba(X)[0, 1])

        # Phase 4 threshold.
        prediction = (
            "PHISHING"
            if probability >= THRESHOLD
            else "BENIGN"
        )

        risk_score = int(np.clip(round(probability * 100), 0, 100))
        level = risk_level(risk_score)

        # User-facing security action is deliberately separate from the
        # Phase 4 ML prediction threshold.
        if level == "SAFE":
            decision = "ALLOW"
        elif level == "LOW RISK":
            decision = "REVIEW"
        elif level == "SUSPICIOUS":
            decision = "WARN"
        else:
            decision = "BLOCK"

        return {
            "url": url,
            "phishing_probability": round(probability, 6),
            "risk_score": risk_score,
            "risk_level": level,
            "prediction": prediction,
            "decision": decision,
            "threshold": THRESHOLD,
            "reasons": generate_reasons(url, features),
        }

    def predict_batch(
        self,
        input_csv: Path,
        output_csv: Path = DEFAULT_OUTPUT,
    ) -> pd.DataFrame:
        df = pd.read_csv(input_csv)

        if "url" not in df.columns:
            raise ValueError(
                f"Input file must contain a 'url' column: {input_csv}"
            )

        results = []

        for url in df["url"].astype(str):
            result = self.predict(url)
            results.append({
                "url": result["url"],
                "phishing_probability": result["phishing_probability"],
                "risk_score": result["risk_score"],
                "risk_level": result["risk_level"],
                "prediction": result["prediction"],
                "decision": result["decision"],
                "threshold": result["threshold"],
                "reasons": " | ".join(result["reasons"]),
            })

        result_df = pd.DataFrame(results)

        # Preserve the original label when available for validation.
        if "label" in df.columns:
            result_df.insert(
                1,
                "actual_label",
                df["label"].astype(str).values,
            )

        output_csv = Path(output_csv)
        output_csv.parent.mkdir(parents=True, exist_ok=True)
        result_df.to_csv(output_csv, index=False)

        return result_df


# ---------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="AI WatchDog Phase 5 inference engine"
    )

    parser.add_argument(
        "url",
        nargs="?",
        help="Single URL to classify",
    )

    parser.add_argument(
        "--batch",
        type=Path,
        help="CSV containing a 'url' column",
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"Batch output CSV (default: {DEFAULT_OUTPUT})",
    )

    parser.add_argument(
        "--model",
        type=Path,
        default=MODEL_PATH,
        help=f"Phase 4 model artifact (default: {MODEL_PATH})",
    )

    args = parser.parse_args()

    if not args.url and not args.batch:
        parser.error("Provide a URL or use --batch INPUT.csv")

    detector = WatchDogDetector(args.model)

    if args.url:
        result = detector.predict(args.url)
        print(json.dumps(result, indent=2))

    if args.batch:
        result_df = detector.predict_batch(args.batch, args.output)

        print("\nAI WatchDog - PHASE 5 BATCH INFERENCE")
        print("=" * 60)
        print(f"Input rows : {len(result_df):,}")
        print(f"Output     : {args.output}")

        print("\nPrediction distribution:")
        print(result_df["prediction"].value_counts().to_string())

        print("\nRisk distribution:")
        print(result_df["risk_level"].value_counts().to_string())

        print("\nComplete.")


if __name__ == "__main__":
    main()
