from contextlib import asynccontextmanager
import hmac
import json
import os
from typing import Optional

from fastapi import FastAPI, HTTPException, Request, status
from pydantic import BaseModel, Field
from fastapi.responses import JSONResponse

from .config import (
    API_HOST,
    API_PORT,
    EXPECTED_MODEL_SHA256,
    MAX_URL_LENGTH,
    MODEL_PATH,
    LOCAL_TOKEN_FILE,
)
from .integrity import ModelIntegrityError, verify_model
from .pe_analyzer.router import router as pe_analysis_router

from phase5_inference import WatchDogDetector


class PredictRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=MAX_URL_LENGTH)


detector: Optional[WatchDogDetector] = None
model_error: Optional[str] = None
verified_model_sha256: Optional[str] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global detector, model_error, verified_model_sha256

    detector = None
    model_error = None
    verified_model_sha256 = None

    try:
        # IMPORTANT: verify the artifact before loading it for inference.
        verified_model_sha256 = verify_model(
            MODEL_PATH,
            EXPECTED_MODEL_SHA256,
        )

        detector = WatchDogDetector(MODEL_PATH)

    except (ModelIntegrityError, FileNotFoundError, OSError, RuntimeError) as exc:
        # Fail closed: the API process may remain reachable for health
        # diagnostics, but it will never perform inference with an
        # untrusted/unverified model.
        model_error = str(exc)

    yield

    detector = None


app = FastAPI(
    title="AI WatchDog ML Service",
    version="6.2.1",
    description=(
        "Hardened URL phishing inference with an isolated, local-only static PE analysis endpoint. "
        "PE indicators and scores are heuristic and do not constitute a malware verdict."
    ),
    lifespan=lifespan,
)
app.include_router(pe_analysis_router)


def _service_token() -> Optional[str]:
    override = os.getenv("AI_WATCHDOG_SPRING_TO_ML_TOKEN", "").strip()
    if len(override) >= 64 and all(char in "0123456789abcdefABCDEF" for char in override):
        return override
    try:
        with LOCAL_TOKEN_FILE.open("r", encoding="utf-8") as handle:
            value = json.load(handle).get("springToMl")
        return (
            value
            if isinstance(value, str)
            and len(value) >= 64
            and all(char in "0123456789abcdefABCDEF" for char in value)
            else None
        )
    except (OSError, ValueError, AttributeError):
        return None


@app.middleware("http")
async def require_service_credential(request: Request, call_next):
    if request.url.path == "/health" and request.method == "GET":
        return await call_next(request)
    expected = _service_token()
    if expected is None:
        return JSONResponse(
            status_code=503,
            content={"error": "LOCAL_AUTH_NOT_CONFIGURED", "message": "Local API credentials are not configured."},
        )
    authorization = request.headers.get("authorization", "")
    supplied = authorization[7:] if authorization.startswith("Bearer ") else ""
    if not supplied or not hmac.compare_digest(expected, supplied):
        return JSONResponse(
            status_code=401,
            content={"error": "INVALID_CREDENTIAL", "message": "A valid service credential is required."},
        )
    return await call_next(request)


@app.get("/health")
def health():
    if detector is None or _service_token() is None:
        error = model_error if detector is None else "Local service credentials are not configured."
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "status": "NOT_READY",
                "model_loaded": detector is not None,
                "model_integrity": "VERIFIED" if verified_model_sha256 else "FAILED",
                "service_auth_configured": _service_token() is not None,
                "error": error,
            },
        )

    return {
        "status": "OK",
        "model_loaded": True,
        "model_integrity": "VERIFIED",
        "service_auth_configured": True,
        "model_sha256": verified_model_sha256,
    }


@app.get("/auth-check")
def auth_check():
    # This endpoint is reachable only after middleware validates Spring's service token.
    return {"status": "OK", "service_auth": "VERIFIED"}


@app.post("/predict")
def predict(request: PredictRequest):
    if detector is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "status": "NOT_READY",
                "message": "ML model is unavailable or failed integrity verification.",
            },
        )

    url = request.url.strip()

    if not url:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="URL must not be empty or whitespace.",
        )

    try:
        return detector.predict(url)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Prediction failed.",
        ) from exc


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "api.server:app",
        host=API_HOST,
        port=API_PORT,
        reload=False,
    )
