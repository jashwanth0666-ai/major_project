"""Deterministic, explainable heuristic weights for static PE evidence."""

BASELINE = 10
WEIGHTS = {
    "writable_executable_section": 25,
    "high_entropy_section": 15,
    "sensitive_imports": 15,
    "file_boundary_anomaly": 20,
    "entry_point_anomaly": 10,
}


def score_indicators(
    *,
    writable_executable_section: bool,
    high_entropy_section: bool,
    sensitive_imports: bool,
    file_boundary_anomaly: bool,
    entry_point_anomaly: bool,
) -> int:
    """Score independent evidence groups; each group contributes at most once."""
    score = BASELINE
    score += WEIGHTS["writable_executable_section"] * writable_executable_section
    score += WEIGHTS["high_entropy_section"] * high_entropy_section
    score += WEIGHTS["sensitive_imports"] * sensitive_imports
    score += WEIGHTS["file_boundary_anomaly"] * file_boundary_anomaly
    score += WEIGHTS["entry_point_anomaly"] * entry_point_anomaly
    return max(0, min(100, int(score)))
