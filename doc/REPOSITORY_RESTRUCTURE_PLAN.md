# Repository Restructure Plan

## Scope and audit date

This plan is based on the checked-out `main` tree as audited on 2026-10-18.
The working tree already contains unrelated modifications in:

- `backend/RUNNING_BACKEND.md`
- `backend/src/main/java/com/aiwatchdog/backend/fileshield/reputation/SqliteHashReputationAdapter.java`
- `backend/src/test/java/com/aiwatchdog/backend/fileshield/SqliteHashReputationAdapterTest.java`

Those files are outside the restructure scope and will not be reverted or
rewritten.

## Current responsibilities

| Area | Current location | Audit result |
| --- | --- | --- |
| FastAPI application and lifecycle | `api/server.py` | Runtime entry point; registers URL and PE routes, local authentication, model readiness, and fail-closed startup behavior. |
| API configuration and integrity | `api/config.py`, `api/integrity.py` | Required runtime configuration and SHA-256 verification. |
| URL inference | `api/phase5_inference.py` | Runtime detector, feature extraction, explanations, batch inference, and a small CLI are combined in one module. |
| PE analysis | `api/pe_analyzer/` | Existing runtime package; retain in place and preserve its routes and safety controls. |
| Model assets | `ml_model/phase4/` | The calibrated model and risk-engine configuration are required deployment assets. Other checked-in CSV/report files are historical Phase 4 evidence. |
| Python tests | `tests/test_pe_analyzer.py` | PE/API integration coverage; it currently inserts the nonexistent `scripts` directory into `sys.path`, which is stale and will be removed. |
| Java services | `backend/` | Existing Spring Boot service; no package restructure is justified by this task. |
| Desktop UI | `Frontend/` | Existing JavaFX application; no package restructure is justified by this task. |
| Browser extension | `browser-extension/` | Existing MV3 extension; no module restructure is justified by this task. |
| Launch/configuration | Root `.bat` and `.ps1` files | Windows launch flow; update only stale Python path setup and retain working-directory behavior. |
| Offline ML workflows | No tracked `scripts/` directory exists | The pasted request references scripts that are not present in this checkout. No offline training/evaluation script can be moved or deleted. Existing documentation references to those absent scripts will be corrected or explicitly marked as unavailable. |

## Proposed mapping

| Existing path | Proposed path | Reason and compatibility action |
| --- | --- | --- |
| `api/phase5_inference.py` | `api/inference/detector.py` | Put reusable URL inference in a clearly named runtime package. Preserve the public `WatchDogDetector`, feature extraction, threshold, response fields, and batch CLI behavior. |
| *(new)* | `api/inference/__init__.py` | Package marker and narrow public export for runtime inference. |
| `api/server.py` import of `.phase5_inference` | `api.inference.detector` | Remove the stale module coupling while preserving the detector type and startup behavior. |
| `tests/test_pe_analyzer.py` `sys.path` insertion | Removed | The repository root already provides the `api` package; the referenced `scripts` folder is absent and unnecessary. |
| Root ML launch and Python startup documentation | Root `api` package imports | Remove the obsolete `PYTHONPATH=scripts` requirement and update commands to run from the repository root. |
| *(new)* | `doc/ARCHITECTURE.md` | Document the stable folder responsibilities and extension points without adding placeholder services. |

No Java packages, browser-extension modules, model contents, model
configuration, database files, source datasets, or historical reports will be
moved or deleted in the initial implementation.

## Model and API invariants

- Model artifact: `ml_model/phase4/xgboost_calibrated.joblib`.
- SHA-256 observed during audit:
  `b46d8ae98125357a349bc308a9e839a2b1804b2e6bc291931aa72c1e358d69b7`.
- Configured expected SHA-256 in `api/config.py` matches the observed hash.
- `ml_model/phase4/risk_engine_config.json` selects threshold `0.15` and lists the
  same 25 feature names used by the detector.
- `/health`, `/predict`, `/auth-check`, and `/api/analyze-file` contracts remain
  unchanged.
- Model verification remains before model loading and continues to fail closed.

## Reference update plan

1. Move the detector module and update the FastAPI import.
2. Update detector module documentation and its path-independent model/output
   defaults using repository-root resolution.
3. Remove the stale `scripts` path insertion from Python tests.
4. Update root launch scripts and all relevant Markdown examples that mention
   `PYTHONPATH=scripts` or the old detector path.
5. Add the architecture map and document the absence of offline scripts in this
   checkout rather than inventing replacement workflows.
6. Merge useful generated-file rules into `.gitignore`; do not untrack or delete
   unrelated build artifacts in this change.

## Validation plan

1. Check the moved Python modules for syntax/import errors.
2. Import `api.server:app` and verify the PE router remains registered.
3. Verify the model hash and load `WatchDogDetector` from the new module.
4. Compare representative benign and phishing URL predictions before and after
   the move using the unchanged model and feature code.
5. Run the focused Python PE/API tests.
6. Run browser-extension tests if the local Node toolchain is available.
7. Run backend and frontend Maven tests only if practical; do not alter the
   unrelated dirty backend files.
8. Search for stale `phase5_inference`, `scripts`, and old path references.
9. Validate the Windows launch command text and report Windows-only checks that
   cannot be executed in the current session.

## Deletion policy

No source or documentation deletion is planned at audit time. The repository
contains ignored `.venv/` and Maven `target/` build output, but these are not
needed for version control and will remain untouched unless a separate cleanup
request authorizes removal. No required model or security artifact is a
candidate for deletion.
