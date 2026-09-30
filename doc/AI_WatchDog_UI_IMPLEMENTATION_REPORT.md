# AI WatchDog UI Implementation Report

Date: 2026-10-01

## Existing UI inspected

The previous single-scene FXML contained welcome/setup, dashboard, URL scanner, result, activity, insights, settings, and error pages. URL analysis and activity history already used the centralized Spring API client and JavaFX background tasks. The dashboard included simulated threat buttons and placeholder engine/confidence values; system health and dashboard counts were not backend powered. Light/dark CSS existed, but the app offered no theme selector.

## Design system

Replaced the old screen structure with a restrained local-security workspace: narrow quiet navigation rail, clear page hierarchy, porcelain light surfaces, graphite dark surfaces, one teal accent, thin separators, readable system typography, and text-plus-color status indicators. The single `app.css` stylesheet centralizes layout, surfaces, controls, statuses, risk badges, and light/dark presentation. The window opens at 1320 × 860 and supports resizing down to 1000 × 680.

## Screens

- **Dashboard:** Spring/ML health, actual URL event totals/high-risk/block counts from `/api/security-events/stats`, and recent real URL/file/process events. Empty and unavailable states are shown; no placeholder numbers remain.
- **Analyze URL:** HTTP/HTTPS input, in-progress state, retryable error state, and a result hierarchy for backend risk, prediction, policy decision, probability, score, and reasons.
- **History:** recent URL and monitor event rows, risk/decision filters, reset and refresh, loading, empty, no-match, and unavailable states.
- **Monitoring:** Spring/ML health and actual file/process observer state. Local file/process collection has explicit Start/Stop controls and begins only after the user starts it.
- **Settings:** persistent Light/Dark/System choice, active backend base URL, connection status, and a concise explanation of the product’s monitoring limits.

## Themes, motion, assets

- Light, dark, and system themes apply without restart and persist in user preferences. System detection uses the host OS setting where available.
- Page transitions and theme changes use brief fades. URL score bars animate to the exact backend score; controls have restrained hover and focus states. No continuous animation loops are used.
- No external imagery or downloaded assets were added. Icons use the existing Ikonli Feather pack dependency, whose Maven metadata declares Apache-2.0.

## Backend wiring

All requests go through `ApiService` to Spring: `GET /api/v1/health`, `POST /api/v1/analyze`, `GET /api/security-events`, `GET /api/security-events/stats`, and `GET/POST /api/monitor-events`. The endpoint base is configurable with `AI_WATCHDOG_BACKEND_URL` or `aiwatchdog.backend.url`. No frontend ML, risk, or policy logic was added. Dashboard/history refresh and URL analysis run on background executors; UI updates return to the JavaFX thread.

## Verification

- `mvn test`: 5 passed, including REST contract mapping, distinct degraded Spring/ML health handling, file monitoring, and process monitoring.
- `mvn '-Dtest=ApiServiceLiveIT,MonitorServicesIntegrationIT' test` with FastAPI and Spring active: 3 passed across live URL analysis/history/stats and file/process event routing.
- `mvn javafx:run`: FXML and CSS loaded without FXML/CSS parser errors. Maven still reports six existing JavaFX dependency model warnings, and Java 24 emits JavaFX native/Unsafe warnings.
- JavaFX app and browser UI surfaces were not exposed to the UI automation environment. Screens, theme switching, resizing, and interaction were therefore not visually inspected.

## Status and remaining limits

**PARTIALLY COMPLETE.** Core screens, data wiring, themes, loading/error/empty states, and service controls are implemented and compile. Visual polish and responsive behavior still need human desktop review. Backend status refreshes every 15 seconds. File/process policy outcomes are audit records; they do not deny access or terminate processes. The optional browser extension is not installed or verified in a browser.
