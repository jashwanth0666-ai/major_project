# AI WatchDog Frontend Runtime Verification

Date: 2026-09-15

## Environment and Commands

Environment:

- OS: Windows 11
- Python: 3.13.12
- Java: 24.0.2
- Maven: 3.9.14
- Documented `.venv` was absent; system Python was used.

Documented commands used:

```powershell
$env:PYTHONPATH = "$PWD\scripts"
python -m uvicorn api.server:app --host 127.0.0.1 --port 8000
```

```powershell
Push-Location backend
.\mvnw.cmd spring-boot:run
Pop-Location
```

```powershell
Push-Location Frontend
mvn clean javafx:run
Pop-Location
```

The documented startup order was followed: FastAPI, Spring Boot, then JavaFX.

## Repository State

Initial and final repository state:

- Branch: `main`
- Commit: `52301b004a5359c8e3ad361719c06270456e5f86`
- Working tree: dirty before and after verification

Pre-existing changes include frontend source/resources, generated `Frontend/target` files, deleted root documentation, untracked documentation under `doc/`, and Phase 1 ML parity files. No source files were changed during this runtime verification.

The `mvn clean javafx:run` command regenerated frontend target output. Those generated changes remain part of the existing dirty-tree state and were not reverted.

## Service Evidence

### FastAPI ML service

Status: **Passed**

Observed startup log:

```text
Application startup complete.
Uvicorn running on http://127.0.0.1:8000
```

Health response:

```json
{
  "status": "OK",
  "model_loaded": true,
  "model_integrity": "VERIFIED"
}
```

### Spring Boot backend

Status: **Passed**

Observed startup log:

```text
Tomcat started on port 8080
Started BackendApplication
```

Health response:

```json
{
  "spring_boot": "UP",
  "status": "OK",
  "ml_service": "UP"
}
```

Safe analysis request:

```json
{ "url": "https://example.com" }
```

Observed response:

```json
{
  "url": "https://example.com",
  "phishing_probability": 0.000873,
  "risk_score": 0,
  "risk_level": "SAFE",
  "prediction": "BENIGN",
  "decision": "ALLOW",
  "threshold": 0.15,
  "reasons": ["No major URL-level warning indicators detected"]
}
```

### JavaFX frontend

Status: **Passed for process startup**

The documented command reached `javafx:run`, compiled 15 source files, and a responsive Java process exposed the window title:

```text
AI WatchDog | Phishing Detection & Secure Access
```

No FXML, resource, controller-construction, or binding exception appeared in the launch output.

Observed environmental/runtime warnings:

```text
Use --enable-native-access=javafx.graphics to avoid a warning
A terminally deprecated method in sun.misc.Unsafe has been called
```

These warnings came from JavaFX graphics/Marlin under Java 24. They did not prevent the window from starting.

## UI Test Matrix

Native JavaFX click/type/readback automation was not available in this environment. Browser automation tools cannot control this native JavaFX window. Accordingly, interaction-dependent checks are explicitly blocked rather than inferred from source code.

| Check                                          | Result  | Evidence                                                                                                                                                           |
| ---------------------------------------------- | ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Initial backend status while checking          | Blocked | Requires observing the JavaFX scene during `refreshBackendStatus()`. Source initializes `ENGINE CHECKING` and `CHECKING`, but this was not observed interactively. |
| Backend status online                          | Blocked | Backend health passed independently; JavaFX status-label update was not directly observed.                                                                         |
| Backend status offline                         | Blocked | Requires stopping/unavailable backend while observing the JavaFX scene. Not performed because interaction/readback was unavailable.                                |
| JavaFX startup and window creation             | Passed  | `mvn clean javafx:run` completed the launch path; expected responsive window title was observed.                                                                   |
| Manual URL analysis with `https://example.com` | Blocked | Backend request passed independently, but entering the URL and submitting through JavaFX could not be automated/read back.                                         |
| Prediction and policy display                  | Blocked | API returned `BENIGN`, `SAFE`, and `ALLOW`; frontend label rendering was not directly observed in this run.                                                        |
| Risk score and progress-bar consistency        | Blocked | Requires observing the JavaFX result screen and progress control.                                                                                                  |
| Confidence/probability display                 | Blocked | Source binds confidence from API probability, but visual runtime observation was unavailable.                                                                      |
| Activity entries and counters                  | Blocked | Requires a JavaFX analysis completion and scene readback.                                                                                                          |
| Empty/invalid input handling                   | Blocked | Requires typing/clicking and reading the JavaFX toast.                                                                                                             |
| Backend error display                          | Blocked | Backend health and API responses passed, but JavaFX error-page rendering was not observed.                                                                         |
| Retry after failure                            | Blocked | Requires sequential JavaFX interaction.                                                                                                                            |
| Repeated submission protection                 | Blocked | Requires submitting during an active JavaFX task.                                                                                                                  |
| Loading cleanup after success/failure          | Blocked | Requires observing the progress indicator and button state.                                                                                                        |
| Toast layering and dismissal                   | Blocked | Source calls `toast.toFront()` and schedules dismissal, but no native visual observation was available.                                                            |
| Disabled unavailable controls                  | Blocked | FXML marks unsupported persistence and enforcement checkboxes disabled; functional click behavior was not observed.                                                |
| Light theme readability                        | Blocked | No automated native screenshot/readback was available in this run.                                                                                                 |
| Dark theme readability                         | Blocked | No automated native screenshot/readback was available in this run.                                                                                                 |

## Screenshots

No screenshots were produced by this verification run. The environment exposed the JavaFX process/window title but did not provide native JavaFX screenshot or control automation.

## Defects Found

No new defect was directly reproduced during this verification.

The following remain unverified rather than passed:

- JavaFX status transitions.
- Result labels and progress-bar rendering.
- Toast z-order and dismissal.
- Invalid-input toast behavior.
- Retry and repeated-submission behavior.
- Disabled-control behavior.
- Light/dark visual readability.

## Compile Result

The frontend compile phase completed successfully as part of:

```powershell
Push-Location Frontend
mvn clean javafx:run
Pop-Location
```

Observed compiler output:

```text
Compiling 15 source files with javac [debug release 17]
```

No Java compilation errors were reported.

## Final Scope Audit

No application source, model, backend, policy, threshold, risk-band, or Member 4 event-logger files were modified during this verification.

Only the required runtime processes were started and stopped. Final port check:

```text
No listeners on ports 8000 or 8080.
```

## Verification Conclusion

The ML service, Spring Boot backend, safe API analysis, JavaFX compilation, JavaFX process startup, and window creation passed. The frontend is **not fully runtime verified** because all native interaction and visual state checks remain blocked by the lack of JavaFX desktop automation/readback in this environment.

A manual Windows UI pass or TestFX-based test run is required before declaring the frontend fully verified.
