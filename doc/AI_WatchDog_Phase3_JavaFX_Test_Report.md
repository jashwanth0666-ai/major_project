# AI WatchDog Phase 3: JavaFX UI Automation and Regression Tests

Date: 2026-09-15

## Initial and Final Git State

Initial and final repository identity:

- Branch: `main`
- Commit: `52301b004a5359c8e3ad361719c06270456e5f86`
- Working tree: dirty before and after Phase 3

Pre-existing changes were preserved, including frontend source/resources, generated `Frontend/target` files, deleted root documentation, untracked documentation, Phase 1 ML parity files, and the prior runtime verification report.

Phase 3 added or changed only:

- `Frontend/pom.xml`
- `Frontend/src/main/java/com/aiwatchdog/controller/MainController.java`
- `Frontend/src/test/java/com/aiwatchdog/controller/MainControllerTest.java`
- `AI_WatchDog_Phase3_JavaFX_Test_Report.md`

The Maven test run generated/updated normal `Frontend/target` test outputs. No backend, ML, model, policy, threshold, risk-band, or Member 4 files were changed.

## Test Strategy

The frontend uses:

- Java release: 17
- JavaFX: 21.0.6
- Maven: 3.9.14
- JDK used for tests: 24.0.2

Added test framework:

- JUnit Jupiter API/Engine: 5.11.4
- TestFX JUnit 5: 4.0.18
- Maven Surefire: 3.5.2

The tests use `ApplicationExtension`, load the real `/fxml/main.fxml`, create a real JavaFX `Scene`, and drive visible controls with `FxRobot`.

The controller now has a package-scoped constructor accepting `ApiService`. The public no-argument constructor remains unchanged for normal FXML loading. Tests inject a deterministic fake API service, so ordinary frontend tests do not require FastAPI or Spring Boot.

### Behaviors covered by controller/scene tests

- Valid URL submission.
- API result rendering.
- Risk score and risk-progress binding.
- Probability-derived confidence display.
- Prediction/policy summary display.
- Manual scan counters.
- Empty and malformed input validation.
- Backend offline status display.
- Disabled unavailable controls.
- Overlapping-analysis prevention.
- Failure error display.
- Loading cleanup through analyze-button re-enablement.
- Retry after a failed analysis.

### Behaviors requiring live services

The deterministic tests do not verify network transport. Live FastAPI/Spring Boot integration remains a separate concern and was previously verified independently during runtime smoke testing.

### Display/headless limitations

The tests ran with a JavaFX toolkit on the Windows desktop environment. No headless Monocle configuration was added because the project uses JavaFX 21.0.6 and JDK 24.0.2, while the commonly documented TestFX Monocle artifacts are older. These tests are therefore headed/native-toolkit tests, not CI-safe headless tests.

## Test Matrix

| Test                                                                  | Result                   | What it genuinely verifies                                                                                                                                               |
| --------------------------------------------------------------------- | ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `validAnalysisRendersResponseAndUpdatesRiskState`                     | Passed                   | Loads real FXML, clicks real navigation/input/button controls, renders fake API response, checks result labels, confidence, policy summary, counter, and progress value. |
| `emptyAndMalformedInputsShowValidationToast`                          | Passed                   | Drives the real scanner input and button, verifies both validation toast messages, and confirms no API call is made.                                                     |
| `backendHealthStatusRendersOfflineAndUnavailableControlsStayDisabled` | Passed                   | Uses a fake offline health response, verifies visible offline badge/footer/protection text, and checks unavailable controls are disabled in the real settings scene.     |
| `overlappingSubmissionIsRejectedWhileFirstAnalysisIsRunning`          | Passed                   | Holds the first fake analysis open, attempts another real UI action, verifies the duplicate toast and confirms only one API analysis call occurs.                        |
| `failedAnalysisCleansUpAndRetryRendersTheNextResult`                  | Passed                   | Forces a fake backend failure, verifies the real error page, confirms the analyze button is re-enabled, retries with a valid URL, and verifies the result page recovers. |
| Live FastAPI/Spring Boot frontend transport                           | Not run in Phase 3 tests | Tests intentionally use a deterministic fake service and do not require network access. Live service behavior was separately verified in the runtime report.             |
| Light-theme screenshot/readability regression                         | Not run                  | No screenshot assertion was added.                                                                                                                                       |
| Dark-theme screenshot/readability regression                          | Not run                  | No screenshot assertion was added.                                                                                                                                       |
| Headless CI execution                                                 | Not run                  | No Monocle/headless configuration was introduced.                                                                                                                        |

## Exact Commands and Results

Initial focused test attempt:

```powershell
Push-Location Frontend; mvn -q -Dtest=MainControllerTest test; $exitCode = $LASTEXITCODE; Pop-Location; exit $exitCode
```

The first attempt reached the JavaFX scene but failed because the test used the text selector `GET STARTED`, while the visible FXML text includes an arrow. This was a test selector defect; it was corrected to use the existing `.get-started-button` and `.large-button` selectors.

Final focused test command:

```powershell
Push-Location Frontend; mvn -q -Dtest=MainControllerTest test; $exitCode = $LASTEXITCODE; Pop-Location; exit $exitCode
```

Final result:

```text
Tests run: 5, Failures: 0, Errors: 0, Skipped: 0
Time elapsed: 31.99 s
```

Frontend compile command:

```powershell
Push-Location Frontend; mvn -q -DskipTests compile; $exitCode = $LASTEXITCODE; Pop-Location; exit $exitCode
```

Result: completed successfully with no compiler errors.

Test warnings:

- JavaFX classes loaded from an unnamed module.
- Java 24 restricted native-access warning.
- JavaFX Marlin used a terminally deprecated `Unsafe` method.

The failure test intentionally prints `Test backend failure` because the existing production controller calls `printStackTrace()` in its failure callback. The test still passed and no real backend error or secret was exposed.

## Files Changed and Rationale

### `Frontend/pom.xml`

Added JUnit 5, TestFX JUnit 5, and Surefire test dependencies/configuration.

### `Frontend/src/main/java/com/aiwatchdog/controller/MainController.java`

Added a minimal constructor-injection seam for `ApiService`:

- `public MainController()` remains available to FXML.
- Package-scoped `MainController(ApiService)` enables deterministic frontend tests.

No runtime behavior was otherwise changed.

### `Frontend/src/test/java/com/aiwatchdog/controller/MainControllerTest.java`

Added five TestFX scene tests using the real FXML and a fake API service.

## Scope Audit

Verified after the test run:

- Phase 1 inference changes remain untouched by Phase 3.
- Backend tracked source diff remains unchanged.
- Existing `ApiService` changes remain untouched by Phase 3.
- No model artifacts, thresholds, risk bands, policy code, browser-monitoring code, persistence code, or Member 4 files changed.
- No production feature was added.

The existing dirty frontend and documentation changes remain preserved.

## Remaining Limitations

- TestFX coverage is headed/native-toolkit based and has not been proven on a headless CI agent.
- No screenshot pixel assertions were added for light or dark themes.
- Live frontend-to-backend transport is not part of ordinary tests.
- The existing controller logs full exception stack traces to the console during failures; the failure test observed this expected behavior.
- The frontend is not declared fully runtime verified across every visual/theme scenario solely from this test suite.

## Phase 3 Status

**Completed for focused JavaFX interaction regression coverage.**

The previously blocked interaction-dependent behaviors now have repeatable TestFX coverage using a real JavaFX scene and deterministic API responses. Live-service integration and cross-environment visual verification remain separate checks.
