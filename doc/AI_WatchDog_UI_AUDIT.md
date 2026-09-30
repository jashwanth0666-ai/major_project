# AI WatchDog JavaFX UI Audit

Audit date: 2026-10-01

## Existing implementation

- JavaFX uses one FXML scene with welcome/setup screens and hidden dashboard, URL scanner, result, activity, insights, settings, and error pages.
- `ApiService` centralizes REST calls to Spring (`/api/v1/analyze`, `/api/v1/health`, URL history, and monitor history). It does not call FastAPI or SQLite.
- `MainController` uses JavaFX `Task` for URL analysis and history, and combines URL/file/process history with risk and decision filters.
- Light and dark CSS files and a `ThemeManager` exist. Theme mode is system-only at startup; settings do not change it.
- The dashboard has simulated threat buttons and hard-coded engine/confidence labels. Dashboard event metrics and connection states are not sourced from Spring.
- The monitor setup flow starts local file/process monitors; current activity/status feedback is transient or limited to the Activity page.
- FXML has substantial placeholder pages, including offline insights and unavailable policy controls. Existing logo/background assets and AtlantaFX/Ikonli dependencies are available.
- Frontend Maven tests cover file/process monitor services; no UI startup, rendering, response mapping, theme-switch, or controller tests were present at audit time.

## Design and implementation plan

Use a calm, original security workspace with a quiet sidebar, warm light surfaces, graphite dark surfaces, and one teal accent. Replace simulated/placeholder content with Dashboard, Analyze, History, Monitoring, and Settings pages backed only by existing Spring endpoints. Preserve asynchronous network work and existing URL, policy, monitor, and history contracts. Add concise empty/error/loading states and functional Light/Dark/System controls. No new visual assets or backend endpoints are required.
