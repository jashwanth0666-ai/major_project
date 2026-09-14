from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, Field

from .config import (
    API_HOST,
    API_PORT,
    EXPECTED_MODEL_SHA256,
    MAX_URL_LENGTH,
    MODEL_PATH,
)
from .integrity import ModelIntegrityError, verify_model

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
    description="Hardened URL phishing inference service.",
    lifespan=lifespan,
)


@app.get("/health")
def health():
    if detector is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "status": "NOT_READY",
                "model_loaded": False,
                "model_integrity": "FAILED",
                "error": model_error,
            },
        )

    return {
        "status": "OK",
        "model_loaded": True,
        "model_integrity": "VERIFIED",
        "model_sha256": verified_model_sha256,
    }


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
