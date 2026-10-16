# AI WatchDog JavaFX Desktop

The desktop uses a calm, light/dark/system theme and a sidebar workspace for Dashboard, Analyze URL, History, Monitoring, and Settings. It uses Spring REST as the only application backend; it does not connect directly to FastAPI or SQLite. URL analysis goes through Spring, which calls the Python model, applies Java policy, and writes the URL audit event. On Windows systems with a supported notification area, the desktop can minimize to its tray, open the alert history, and show notifications for new WARN/BLOCK events. Tray support is optional; closing the app through the tray Exit item shuts down the JavaFX monitor services cleanly.

## Run

Requirements: JDK 17+ and Maven 3.9+. From the repository root:

```powershell
cd Frontend
mvn javafx:run
```

Start FastAPI and Spring Boot first for live URL analysis and history. Use the root `start-aiwatchdog.bat` for readiness-checked startup.

File and process observation starts only when the user selects **Start local monitoring** on the Monitoring page. Select **Stop local monitoring** to end the current session. Configure local file roots from **Settings → Local Monitoring**; the selection is saved per user and applied to an active local watcher. `AI_WATCHDOG_MONITOR_DIRS` remains a first-run fallback when no UI selection has been saved. `AI_WATCHDOG_MONITOR_EXCLUDE` and `AI_WATCHDOG_PROCESS_POLL_MS` remain optional environment/JVM settings.

The dashboard shows backend URL event totals and separate lifetime unified-assessment totals, verdicts, partial outcomes, and file reputation categories. It reads assessment aggregates from `GET /api/security-events/assessments/stats` and never treats an unavailable response as zero. An unavailable aggregate appears as `N/A`. **Settings → File Shield** configures approved scan roots, the local reputation database, scan limits, and the optional Spring watcher; updates apply at runtime and persist under `%APPDATA%/AIWatchDog/file-shield-settings.json` (or `~/.aiwatchdog/` when `%APPDATA%` is unavailable). The settings endpoint is limited to loopback clients. Theme selection is saved locally. To configure the backend endpoint, set `AI_WATCHDOG_BACKEND_URL` or JVM property `aiwatchdog.backend.url`; the default is `http://127.0.0.1:8080`.

For active browser tab URLs, load the optional Chromium extension from `../browser-extension/`; the project does not install it automatically.

The Activity page reads bounded URL, monitor, and unified assessment history through Spring. The unified assessment endpoint returns the latest 100 rows; Activity adds local date/type/status filters and 10-row paging. Select an assessment row to inspect its identifier, correlation ID, source results, explanations, and source errors. File subjects are displayed by shortened SHA-256, not local path. `WARN` and `BLOCK` on file/process events are recorded policy outcomes. They do not block operating-system access or terminate processes.

The sidebar protection indicator is derived from Spring/ML health and the backend File Shield watcher state. It reports unavailable states explicitly; it does not represent a firewall, antivirus engine, or OS enforcement policy. Tray notifications contain only source type, risk level, and policy decision. They are generated from newly observed persisted WARN/BLOCK events; the first history snapshot is used as a baseline, so existing events are not replayed as new alerts.

Defender telemetry, script monitoring, and process correlation have independent switches in **Settings → Local Monitoring**. Settings shows provider state, permission errors, last event timestamps, and collector drops/restarts. Script monitoring combines bounded static inspection of changed scripts in active File Shield watch roots with PowerShell event 4104 when Script Block Logging is configured. Process correlation uses Security events 4688/4689 when available. Script contents and command lines are analyzed transiently and are not persisted. Read permissions and audit policies depend on Windows configuration; the app does not elevate or change those policies. See [the Windows telemetry event map and limitations](../backend/MONITORING.md#windows-defender-and-security-event-telemetry).

Spring Boot remains the only frontend data source. No new database or migration is introduced for the dashboard; assessment totals are calculated from the existing `security_events` table.

See [backend/MONITORING.md](../backend/MONITORING.md) for collection scope, rules, privacy behavior, endpoints, and limitations.
