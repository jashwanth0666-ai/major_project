import os
from pathlib import Path

# Project root: ai_watchdog_phase6_2_1/
PROJECT_ROOT = Path(__file__).resolve().parents[1]

API_HOST = os.getenv("AI_WATCHDOG_API_HOST", "127.0.0.1")
API_PORT = int(os.getenv("AI_WATCHDOG_API_PORT", "8000"))

MODEL_PATH = PROJECT_ROOT / os.getenv(
    "AI_WATCHDOG_MODEL_PATH",
    "data/phase4/xgboost_calibrated.joblib",
)

# Frozen SHA-256 for the approved Phase 4 calibrated model.
EXPECTED_MODEL_SHA256 = os.getenv(
    "AI_WATCHDOG_MODEL_SHA256",
    "B46D8AE98125357A349BC308A9E839A2B1804B2E6BC291931AA72C1E358D69B7",
).strip().lower()

MAX_URL_LENGTH = int(os.getenv("AI_WATCHDOG_MAX_URL_LENGTH", "4096"))
