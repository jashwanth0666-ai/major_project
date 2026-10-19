"""Compare full-URL and scheme-plus-host inference with the frozen model.

Input CSV schema: required columns ``url`` and ``label``; labels must be
``benign`` or ``phishing``. Optional ``source`` and ``scenario`` columns are
accepted but ignored. Supply an evaluation split and its training CSV; the
command rejects any exact hostname overlap.

Reproduce the repository validation comparison from the project root:
    python -m api.inference.evaluate_url_representations \
        --training-data ml_model/splits/train.csv \
        --evaluation-data ml_model/splits/validation.csv

No model is trained, no threshold is selected, and no row-level URLs are emitted.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
from importlib.metadata import PackageNotFoundError, version
import ipaddress
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

import numpy as np
import pandas as pd

from api.inference.detector import (
    FEATURES,
    MODEL_PATH,
    SUSPICIOUS_KEYWORDS,
    THRESHOLD,
    WatchDogDetector,
    extract_features,
)
from api.inference.url_normalization import normalize_host_inference_url


_LONG_NUMERIC_PATH_SEGMENT = re.compile(r"^\d{6,}$")


def _package_version(name: str) -> str | None:
    try:
        return version(name)
    except PackageNotFoundError:
        return None


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _host(url: str, row_number: int, require_http_scheme: bool = True) -> str:
    try:
        parsed = urlsplit(url)
        host = parsed.hostname
        if not host:
            raise ValueError("Missing hostname.")
        if not require_http_scheme:
            host = host.rstrip(".").lower()
            try:
                return ipaddress.ip_address(host).compressed.lower()
            except ValueError:
                if ":" in host:  # Preserve scoped IPv6 literals for grouping; they are rejected as inference inputs.
                    return host
                try:
                    return host.encode("idna").decode("ascii").lower()
                except UnicodeError:
                    # Keep malformed training host text grouped consistently rather than silently dropping it.
                    return host
        if parsed.scheme.lower() not in {"http", "https"}:
            raise ValueError("Unsupported scheme.")
        return urlsplit(normalize_host_inference_url(url)).hostname.lower()
    except (AttributeError, ValueError) as exc:
        raise ValueError(f"Invalid URL at CSV row {row_number}: {exc}") from exc


def _read_training_hosts(path: Path) -> tuple[set[str], int, int]:
    hosts: set[str] = set()
    rows = 0
    domain_fallback_rows = 0
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        if not reader.fieldnames or "url" not in reader.fieldnames:
            raise ValueError(f"Training CSV must contain a 'url' column: {path}")
        for row_number, row in enumerate(reader, start=2):
            url = (row.get("url") or "").strip()
            if not url:
                raise ValueError(f"Missing URL at training CSV row {row_number}.")
            try:
                host = _host(url, row_number, require_http_scheme=False)
            except ValueError:
                domain = (row.get("domain") or "").strip()
                if not domain:
                    raise ValueError(f"Cannot derive a hostname group at training CSV row {row_number}.")
                host = _host(f"http://{domain}", row_number)
                domain_fallback_rows += 1
            hosts.add(host)
            rows += 1
    if not rows:
        raise ValueError("Training CSV contains no URL rows.")
    return hosts, rows, domain_fallback_rows


def _read_evaluation_rows(
    path: Path,
) -> tuple[list[str], np.ndarray, list[str], list[str], dict[str, int]]:
    urls: list[str] = []
    labels: list[int] = []
    hosts: list[str] = []
    all_group_hosts: list[str] = []
    excluded = {"unsupported_scheme": 0, "invalid_url": 0}
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        if not reader.fieldnames or not {"url", "label"}.issubset(reader.fieldnames):
            raise ValueError(f"Evaluation CSV must contain 'url' and 'label' columns: {path}")
        for row_number, row in enumerate(reader, start=2):
            url = (row.get("url") or "").strip()
            label = (row.get("label") or "").strip().casefold()
            if not url:
                raise ValueError(f"Missing URL at evaluation CSV row {row_number}.")
            if label not in {"benign", "phishing"}:
                raise ValueError(
                    f"Unsupported label at evaluation CSV row {row_number}; expected benign or phishing."
                )
            try:
                group_host = _host(url, row_number, require_http_scheme=False)
            except ValueError:
                domain = (row.get("domain") or "").strip()
                if not domain:
                    raise ValueError(f"Cannot derive a hostname group at evaluation CSV row {row_number}.")
                group_host = _host(f"http://{domain}", row_number)
            all_group_hosts.append(group_host)
            try:
                host = _host(url, row_number)
            except ValueError as exc:
                reason = "unsupported_scheme" if "Unsupported scheme" in str(exc) else "invalid_url"
                excluded[reason] += 1
                continue
            urls.append(url)
            labels.append(int(label == "phishing"))
            hosts.append(host)
    if not urls:
        raise ValueError("Evaluation CSV contains no rows.")
    return urls, np.asarray(labels, dtype=np.int8), hosts, all_group_hosts, excluded


def _assert_hosts_disjoint(training_hosts: set[str], evaluation_hosts: list[str]) -> None:
    overlap_count = len(training_hosts.intersection(evaluation_hosts))
    if overlap_count:
        raise ValueError(
            f"Training/evaluation hostname leakage detected ({overlap_count} shared hosts); use disjoint hostname splits."
        )


def _probability_metrics(labels: np.ndarray, probabilities: np.ndarray) -> dict:
    if len(labels) != len(probabilities):
        raise ValueError("Each evaluated row must have exactly one probability.")
    predictions = probabilities >= THRESHOLD
    tp = int(np.sum((labels == 1) & predictions))
    fp = int(np.sum((labels == 0) & predictions))
    tn = int(np.sum((labels == 0) & ~predictions))
    fn = int(np.sum((labels == 1) & ~predictions))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

    # Expected calibration error with ten fixed probability bins.
    ece = 0.0
    bin_count = 10
    for index in range(bin_count):
        lower = index / bin_count
        upper = (index + 1) / bin_count
        in_bin = (probabilities >= lower) & (
            probabilities <= upper if index == bin_count - 1 else probabilities < upper
        )
        count = int(np.sum(in_bin))
        if count:
            confidence = float(np.mean(probabilities[in_bin]))
            accuracy = float(np.mean(labels[in_bin]))
            ece += (count / len(labels)) * abs(confidence - accuracy)

    return {
        "sample_count": int(len(labels)),
        "threshold": THRESHOLD,
        "confusion_matrix": {"labels": ["benign", "phishing"], "matrix": [[tn, fp], [fn, tp]]},
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_rate": fp / (fp + tn) if fp + tn else None,
        "false_negative_rate": fn / (fn + tp) if fn + tp else None,
        "brier_score": float(np.mean((probabilities - labels) ** 2)),
        "expected_calibration_error_10_bins": ece,
    }


def _cohort_masks(urls: list[str], labels: np.ndarray) -> dict[str, np.ndarray]:
    numeric_benign = []
    phishing_path_signals = []
    for url, label in zip(urls, labels, strict=True):
        parsed = urlsplit(url)
        path_segments = [segment for segment in parsed.path.split("/") if segment]
        numeric_benign.append(
            label == 0 and any(_LONG_NUMERIC_PATH_SEGMENT.fullmatch(segment) for segment in path_segments)
        )
        path_query = f"{parsed.path}?{parsed.query}".casefold()
        phishing_path_signals.append(
            label == 1 and any(keyword in path_query for keyword in SUSPICIOUS_KEYWORDS)
        )
    return {
        "benign_with_long_numeric_path_segment": np.asarray(numeric_benign, dtype=bool),
        "phishing_with_suspicious_path_or_query_keyword": np.asarray(phishing_path_signals, dtype=bool),
    }


def _feature_frame(urls: list[str]) -> pd.DataFrame:
    rows = [extract_features(url) for url in urls]
    return pd.DataFrame(rows, columns=FEATURES).astype(np.float32)


def evaluate(training_data: Path, evaluation_data: Path, model_path: Path, batch_size: int = 2048) -> dict:
    if batch_size < 1:
        raise ValueError("Batch size must be positive.")
    training_hosts, training_rows, training_domain_fallback_rows = _read_training_hosts(training_data)
    urls, labels, evaluation_hosts, all_group_hosts, excluded_rows = _read_evaluation_rows(evaluation_data)
    overlap_count = len(training_hosts.intersection(all_group_hosts))
    _assert_hosts_disjoint(training_hosts, all_group_hosts)

    detector = WatchDogDetector(model_path)
    full_probabilities: list[float] = []
    host_probabilities: list[float] = []
    for start in range(0, len(urls), batch_size):
        chunk = urls[start : start + batch_size]
        host_chunk = [normalize_host_inference_url(url) for url in chunk]
        full_matrix = _feature_frame(chunk)
        host_matrix = _feature_frame(host_chunk)
        full_probabilities.extend(detector.model.predict_proba(full_matrix)[:, 1].astype(float))
        host_probabilities.extend(detector.model.predict_proba(host_matrix)[:, 1].astype(float))

    full_probs = np.asarray(full_probabilities)
    host_probs = np.asarray(host_probabilities)
    cohorts = _cohort_masks(urls, labels)
    strategy_results = {
        "full_url": _probability_metrics(labels, full_probs),
        "scheme_and_hostname": _probability_metrics(labels, host_probs),
    }
    cohort_results = {}
    for name, mask in cohorts.items():
        cohort_results[name] = {
            "sample_count": int(np.sum(mask)),
            "full_url": _probability_metrics(labels[mask], full_probs[mask]) if np.any(mask) else None,
            "scheme_and_hostname": _probability_metrics(labels[mask], host_probs[mask]) if np.any(mask) else None,
        }

    return {
        "input_schema": {"required_columns": ["url", "label"], "allowed_labels": ["benign", "phishing"]},
        "model_sha256": _sha256(model_path),
        "training_data_sha256": _sha256(training_data),
        "evaluation_data_sha256": _sha256(evaluation_data),
        "training_rows": training_rows,
        "evaluation_rows": len(urls),
        "excluded_evaluation_rows": excluded_rows,
        "evaluation_source_rows": len(all_group_hosts),
        "training_unique_hostnames": len(training_hosts),
        "training_hostname_groups_from_domain_column": training_domain_fallback_rows,
        "evaluation_unique_hostnames_eligible": len(evaluation_hosts),
        "evaluation_unique_hostnames_including_excluded": len(set(all_group_hosts)),
        "shared_training_evaluation_hostnames": overlap_count,
        "runtime_versions": {
            "python": sys.version.split()[0],
            "numpy": np.__version__,
            "pandas": pd.__version__,
            "scikit_learn": _package_version("scikit-learn"),
            "xgboost": _package_version("xgboost"),
        },
        "feature_count": len(FEATURES),
        "threshold": THRESHOLD,
        "strategies": strategy_results,
        "cohorts": cohort_results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compare frozen-model full-URL and scheme-plus-host probabilities on labelled CSV data."
    )
    parser.epilog = (
        "CSV schema: required columns url,label; label is benign or phishing. "
        "Optional columns such as source or scenario are ignored. Training and evaluation hostnames must be disjoint."
    )
    parser.add_argument("--training-data", type=Path, default=Path("ml_model/splits/train.csv"))
    parser.add_argument("--evaluation-data", type=Path, default=Path("ml_model/splits/validation.csv"))
    parser.add_argument("--model", type=Path, default=MODEL_PATH)
    parser.add_argument("--batch-size", type=int, default=2048)
    parser.add_argument("--output", type=Path, help="Optional JSON report path; no URLs are written.")
    args = parser.parse_args()

    try:
        result = evaluate(args.training_data, args.evaluation_data, args.model, args.batch_size)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    rendered = json.dumps(result, indent=2, sort_keys=True, allow_nan=False)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0


if __name__ == "__main__":
    sys.exit(main())
