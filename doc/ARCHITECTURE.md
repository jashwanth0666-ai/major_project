# AI WatchDog Architecture

## Runtime components

```text
api/
├── server.py                 FastAPI application, lifecycle, auth, and routes
├── config.py                 Environment-backed runtime configuration
├── integrity.py              Model SHA-256 verification and fail-closed errors
├── inference/
│   └── detector.py           URL feature extraction, calibrated inference, and explanations
└── pe_analyzer/
    ├── router.py             Static PE HTTP route
    ├── schemas.py            Request and response models
    ├── scoring.py            Deterministic heuristic scoring
    └── service.py            Bounded, non-executing PE parsing
```

`api.server:app` verifies the Phase 4 model before constructing
`WatchDogDetector`. A failed or missing verification leaves the service
reachable for health diagnostics but prevents prediction. The detector remains
deterministic and does not require network access or optional external
providers.

## Supporting applications

- `backend/` contains the Spring Boot API, policy engine, persistence, local
  authentication, monitoring, and the backend-side ML client.
- `Frontend/` contains the JavaFX desktop application. It communicates with
  Spring Boot rather than accessing FastAPI or SQLite directly.
- `browser-extension/` contains the optional Chromium MV3 extension.
- `ml_model/phase4/` contains the approved calibrated model and risk-engine
  configuration. The model is a deployment asset, not generated build output.
- `tests/` contains Python API and PE analyzer tests. Java and extension tests
  remain beside their respective applications.
- `doc/` contains operational, security, evaluation, and architecture
  documentation.

## Offline ML workflows

This checkout does not contain a tracked `scripts/` directory or the
enterprise training/evaluation scripts referenced by some historical reports.
The runtime detector still supports single-URL and CSV batch inference:

```powershell
python -m api.inference.detector https://example.com
python -m api.inference.detector --batch INPUT.csv --output ml_model\phase5\predictions.csv
```

Training, retraining, and external threat-intelligence lookups are not part of
the runtime service and are not enabled by this refactor.

## Extension points

Future threat-intelligence providers and LLM-assisted explanations should be
optional services under `api/services/`, with explicit timeouts and feature
flags. They must consume the deterministic detector output rather than replace
model verification, feature extraction, thresholding, or the existing API
contract.
