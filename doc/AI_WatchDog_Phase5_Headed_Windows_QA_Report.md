# AI WatchDog Phase 5: Headed Windows QA Report

Date: 2026-09-15

## Verdict

**Frontend sign-off: No-Go.**

The current frontend compiles and the JavaFX launch command reaches `javafx:run`, but the required headed UI interactions and screenshots were not successfully exercised. The current FXML also differs from the previously audited dynamic version and contains reverted static runtime claims.

## Initial and Final Git State

Initial state:

- Branch: `main`
- Commit: `52301b004a5359c8e3ad361719c06270456e5f86`
- Working tree: dirty

Pre-existing changes included frontend source/resources, generated frontend target files, deleted root documentation, untracked documentation, Phase 1 files, Phase 3 tests/report, Phase 4 report, and helper files.

Final state remained dirty. No backend, ML, model, policy, threshold, risk-band, or Member 4 source files were modified.

This QA run created untracked screenshots under `qa-screenshots/`. The captured images are invalid QA evidence because they show the VS Code desktop rather than the JavaFX window.

## Environment

- Windows 11
- Python 3.13.12
- Java 24.0.2
- Maven 3.9.14
- JavaFX dependency: 21.0.6
- Maven compiler release: 17

## Exact Commands Used

ML service:

```powershell
$env:PYTHONPATH = "$PWD\scripts"
python -m uvicorn api.server:app --host 127.0.0.1 --port 8000
```

Backend:

```powershell
Push-Location backend
.\mvnw.cmd spring-boot:run
Pop-Location
```

Frontend:

```powershell
Push-Location Frontend
mvn clean javafx:run
Pop-Location
```

Required focused test:

```powershell
Push-Location Frontend
mvn -q -Dtest=MainControllerTest test
Pop-Location
```

Frontend compile:

```powershell
Push-Location Frontend
mvn -q -DskipTests compile
Pop-Location
```

## Service Results

| Check                         | Result           | Evidence                                                                                                                                |
| ----------------------------- | ---------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| FastAPI startup               | Passed           | `Application startup complete`; Uvicorn on `127.0.0.1:8000`.                                                                            |
| Spring Boot startup           | Passed           | Tomcat started on port `8080`; `Started BackendApplication`.                                                                            |
| ML health                     | Passed           | Returned `status=OK`, `model_loaded=true`, `model_integrity=VERIFIED`.                                                                  |
| Backend health                | Passed           | Returned `spring_boot=UP`, `ml_service=UP`, `status=OK`.                                                                                |
| Backend safe analysis         | Passed           | `https://example.com` returned probability `0.000873`, score `0`, `SAFE`, `BENIGN`, `ALLOW`, threshold `0.15`, and the expected reason. |
| JavaFX compilation            | Passed           | `mvn clean javafx:run` compiled 15 sources and reached the JavaFX run goal.                                                             |
| JavaFX process/window startup | Partially passed | A JavaFX window was observed earlier during process inspection, but a reliable foreground/native capture was not obtained in this run.  |

## Current FXML Findings

The current [Frontend/src/main/resources/fxml/main.fxml](Frontend/src/main/resources/fxml/main.fxml) has reverted static content compared with the prior dynamic-status audit. It currently contains:

- `Real-time Inspection`
- `Monitor browser traffic in real-time.`
- `AI Heuristics Engine`
- `Enable advanced zero-day detection.`
- `ENGINE ONLINE`
- `SECURE`
- `REAL-TIME PROTECTION`
- `Neural engine is actively monitoring network packets.`
- `PACKETS INSPECTED`
- `THREATS BLOCKED`
- `MODEL CONFIDENCE` with `99.4%`
- `Telemetry Stream`
- `Sentinel v3.1`
- `modelConfidence` initialized to `99.9%`

These values are not all bound to current backend health or analysis responses in the current FXML. This is a confirmed source-level regression, not merely an unverified visual concern.

The FXML does contain IDs such as `statusBadge`, `riskProgress`, `modelConfidence`, and `threatEngine`, but several values are initialized with static misleading text and some expected dynamic-status controls from the earlier audit are absent or changed.

## Test Matrix

| Test                                                | Result               | Evidence                                                                                                         |
| --------------------------------------------------- | -------------------- | ---------------------------------------------------------------------------------------------------------------- |
| Welcome/setup screen renders without missing assets | Blocked              | JavaFX launched, but a valid JavaFX-window screenshot was not captured.                                          |
| Navigate to manual URL analysis                     | Blocked              | Native AWT clicks did not target the JavaFX window; screenshots showed VS Code.                                  |
| Submit `https://example.com` through JavaFX         | Blocked              | Direct backend request passed, but actual JavaFX submission was not observed.                                    |
| Compare every displayed field with backend response | Blocked              | No valid result-screen screenshot/readback.                                                                      |
| Risk score/progress consistency                     | Blocked              | No valid JavaFX result observation.                                                                              |
| Activity entries/counters                           | Blocked              | No valid JavaFX interaction/readback.                                                                            |
| Empty input validation                              | Blocked              | Native interaction was not successfully targeted.                                                                |
| Malformed input validation                          | Blocked              | Native interaction was not successfully targeted.                                                                |
| Backend stop/offline UI state                       | Blocked              | Native JavaFX interaction unavailable.                                                                           |
| Backend restart/recovery                            | Blocked              | Native JavaFX interaction unavailable.                                                                           |
| Retry/loading cleanup                               | Blocked              | Native JavaFX interaction unavailable.                                                                           |
| Unavailable controls disabled                       | Blocked              | No valid screenshot or native control readback.                                                                  |
| Light theme                                         | Blocked              | No valid JavaFX screenshot.                                                                                      |
| Dark theme                                          | Blocked              | No valid JavaFX screenshot.                                                                                      |
| Toast layering/dismissal                            | Blocked              | No valid JavaFX screenshot or native observation.                                                                |
| JavaFX console errors                               | Passed with warnings | No FXML/resource exception appeared. Java 24 restricted-native-access and deprecated `Unsafe` warnings appeared. |

## TestFX Regression Result

Command:

```powershell
Push-Location Frontend; mvn -q -Dtest=MainControllerTest test; Pop-Location
```

Result:

```text
Tests run: 5, Failures: 0, Errors: 5, Skipped: 0
```

All five tests failed before analysis because the current real FXML scene did not expose the `.large-button` selector expected by the Phase 3 tests:

```text
FxRobotException: the query ".large-button" returned no nodes.
```

This confirms the current FXML and Phase 3 automation tests are out of sync. No fix was made because this QA request required reporting defects and preserving current changes.

## Screenshots

Attempted paths:

- `qa-screenshots/full-desktop.png`
- `qa-screenshots/setup.png`
- `qa-screenshots/dashboard.png`
- `qa-screenshots/scanner.png`
- `qa-screenshots/scanner-filled.png`
- `qa-screenshots/analysis-loading.png`
- `qa-screenshots/analysis-result.png`

These files are **not valid JavaFX evidence**. They show the VS Code desktop because the JavaFX window was not foregrounded for the AWT capture. They must not be used as proof of UI state.

## Defects Found

### Confirmed: current FXML reverted to misleading static runtime claims

File: [Frontend/src/main/resources/fxml/main.fxml](Frontend/src/main/resources/fxml/main.fxml)

Impact:

- UI can claim real-time monitoring without implementation.
- Online/secure status can appear active when backend is unavailable.
- Confidence and engine labels can display fabricated/static values.
- Packet/threat telemetry wording does not reflect the actual manual-analysis workflow.

### Confirmed: Phase 3 TestFX selectors no longer match current FXML

The required suite expects `.large-button`, but the current loaded scene exposes no visible node matching that selector during setup navigation. All five tests fail at this point.

Impact:

- Existing automated regression coverage cannot validate the current frontend.
- Phase 3’s prior passing result does not apply to the current FXML state.

No source fix was made during Phase 5 because the request specified QA verification and defect reporting.

## Compile Result

The frontend compile command completed successfully:

```text
mvn -q -DskipTests compile
```

No Java compilation errors were reported.

## Cleanup

The ML, backend, and frontend processes started for this QA run were stopped. Final port check:

```text
No listeners on ports 8000 or 8080.
```

## Scope Audit

No backend, FastAPI, ML/model, policy-engine, threshold, risk-band, or Member 4 files were changed.

The only QA-generated files were the report and invalid screenshot artifacts. Existing user changes were preserved.

## Remaining Limitations and Required Next Step

Frontend sign-off cannot be granted until:

1. The current FXML/static-content regression is resolved or explicitly accepted.
2. Phase 3 selectors are aligned with the authoritative current FXML.
3. A native JavaFX/TestFX run passes against the current files.
4. A valid foreground JavaFX capture is obtained for welcome, result, error/offline, light-theme, and dark-theme states.
5. Manual or native automated checks cover backend stop/restart, retry, toast dismissal, loading cleanup, and disabled controls.

**Phase 5 status: Blocked.**
