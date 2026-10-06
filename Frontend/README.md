# AI WatchDog JavaFX Desktop

The desktop uses a calm, light/dark/system theme and a sidebar workspace for Dashboard, Analyze URL, History, Monitoring, and Settings. It uses Spring REST as the only application backend; it does not connect directly to FastAPI or SQLite. URL analysis goes through Spring, which calls the Python model, applies Java policy, and writes the URL audit event.

## Run

Requirements: JDK 17+ and Maven 3.9+. From the repository root:

```powershell
cd Frontend
mvn javafx:run
```

Start FastAPI and Spring Boot first for live URL analysis and history. Use the root `start-aiwatchdog.bat` for readiness-checked startup.

File and process observation starts only when the user selects **Start local monitoring** on the Monitoring page. Select **Stop local monitoring** to end the current session. File roots default to the current user's Downloads, Desktop, and Documents directories. Set `AI_WATCHDOG_MONITOR_DIRS` and `AI_WATCHDOG_MONITOR_EXCLUDE` before starting JavaFX to configure watched and excluded paths. Process polling can be configured with `AI_WATCHDOG_PROCESS_POLL_MS`.

The dashboard shows backend URL event totals, recent security history, and actual Spring/ML health state. Theme selection is in Settings and is saved locally. To configure the backend endpoint, set `AI_WATCHDOG_BACKEND_URL` or JVM property `aiwatchdog.backend.url`; the default is `http://127.0.0.1:8080`.

For active browser tab URLs, load the optional Chromium extension from `../browser-extension/`; the project does not install it automatically.

The Activity page reads URL and monitor audit history through Spring and offers risk-level and policy-decision filters. `WARN` and `BLOCK` on file/process events are recorded policy outcomes. They do not block operating-system access or terminate processes.

See [backend/MONITORING.md](../backend/MONITORING.md) for collection scope, rules, privacy behavior, endpoints, and limitations.
