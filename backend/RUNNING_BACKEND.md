# Running the Backend

The backend is a Spring Boot application using Maven and Java 21.

## Prerequisites

- Java 21 installed and available on `PATH`
- PowerShell, Command Prompt, or a Unix-like shell
- The ML API running at `http://127.0.0.1:8000` when ML predictions are needed

Before starting services manually, run `setup-local-auth.ps1` from the repository root. It creates the per-user bearer credentials required by Spring and FastAPI. The root `run-aiwatchdog-backend.bat` and `start-aiwatchdog.bat` scripts initialize them automatically. Configure the extension token separately in the extension Options page; see [the run guide](../doc/RUNNING.md#local-api-credentials).

Check Java from the `backend` directory:

```powershell
java -version
```

## Start the backend

From the repository root:

```powershell
cd backend
.\mvnw.cmd spring-boot:run
```

The backend starts at:

```text
http://localhost:8080
```

To stop it, press `Ctrl+C`.

## Build the backend

```powershell
cd backend
.\mvnw.cmd clean package
```

The packaged JAR is created in `backend/target/`.

Run the packaged application with:

```powershell
java -jar target/backend-0.0.1-SNAPSHOT.jar
```

## Run tests

Run all tests:

```powershell
cd backend
.\mvnw.cmd test
```

Build without running tests:

```powershell
.\mvnw.cmd clean package -DskipTests
```

## Useful Maven commands

```powershell
# Compile the source
.\mvnw.cmd compile

# Clean generated build files
.\mvnw.cmd clean

# Show Spring Boot application information
.\mvnw.cmd spring-boot:help
```

## Run the ML API

From the repository root, create or activate the Python environment used by the API, then run:

```powershell
python -m uvicorn api.server:app --host 127.0.0.1 --port 8000 --reload
```

The backend's ML URL is configured in `backend/src/main/resources/application.properties`:

```properties
ai-watchdog.ml.base-url=http://127.0.0.1:8000
```

If the ML API uses another URL, update that property before starting the backend.

## Security event and monitor APIs

- `GET /api/security-events` returns recent URL analyses.
- `GET /api/security-events/risk/{riskLevel}` and `/decision/{decision}` filter URL analyses.
- `GET /api/security-events/stats` returns URL analysis statistics.
- `GET /api/security-events/assessments` returns recent unified threat-assessment audit events.
- `POST /api/monitor-events` assesses and stores a file/process metadata event.
- `GET /api/monitor-events?limit=100` returns recent file/process assessments.

URL and monitor records share the configured SQLite database path in `ai-watchdog.security.db-path`. File/process decisions are heuristic policy records; this backend does not enforce operating-system access controls.

See [MONITORING.md](MONITORING.md) for event payloads and monitoring limitations.

## Read-only File Shield

Configure approved roots from **JavaFX → Settings → File Shield**. These settings apply immediately and persist in `%APPDATA%/AIWatchDog/file-shield-settings.json`. The backend also accepts indexed defaults in `application.properties`, for example `ai-watchdog.file-shield.allowed-roots[0]=C:/Users/you/Downloads`; use forward slashes in Windows properties paths. With no approved roots configured, scan requests are rejected.

- `POST /api/v1/file-shield/scan` with `{"path":"C:/Users/you/Downloads/sample.txt"}` hashes one regular file.
- `POST /api/v1/file-shield/scan-directory` with `{"path":"C:/Users/you/Downloads"}` scans bounded regular files recursively.
- Defaults: 100 MiB per file, 500 files per directory scan, depth 5. Configure with `ai-watchdog.file-shield.max-file-size`, `max-files-per-directory-scan`, and `max-directory-depth`.
- `ai-watchdog.file-shield.reputation-database-path` defaults to `file_reputation.db`. The database must be provided by a trusted source and contain a `hash_reputation` table; this project does not seed signatures or decide that unlisted hashes are clean. Missing or unreadable reputation data returns `LOOKUP_ERROR` while preserving the calculated hash.
- Expected table columns: `sha256 TEXT PRIMARY KEY`, `reputation TEXT` (`KNOWN_MALICIOUS`, `KNOWN_CLEAN`, or `SUSPICIOUS`), `source TEXT`, `description TEXT`, and `updated_at TEXT`. Populate it only with reputation data from a trusted source; no sample threat records are shipped.
- By default, reputation is local SQLite only. Optional external hash reputation is disabled unless `AI_WATCHDOG_THREAT_INTEL_ENABLED=true`, an HTTPS `AI_WATCHDOG_THREAT_INTEL_ENDPOINT` is configured, and the optional `AI_WATCHDOG_THREAT_INTEL_API_KEY` is supplied. Only the SHA-256 digest is sent. It has bounded timeout, cache, and request-rate settings; provider state appears in Settings. Do not put the API key in source control.
- A manual Quarantine action appears only for known malicious or suspicious scan results. It requires a JavaFX confirmation and the backend rechecks reputation and SHA-256 before a same-volume move into the restricted `.aiwatchdog-quarantine` folder. Restore is separately confirmed and requires a new path within an approved root. Unknown reputation never authorizes quarantine. The watcher and policy engine never trigger quarantine automatically. Operation state uses the existing `security_events` table; no schema migration is required.
- Directory and watcher scans skip Authenticode signature inspection to keep batch work bounded; use single-file scan for signature status. Signatures are inspected through Windows PowerShell and unsigned does not mean malicious.

## Optional real-time File Shield monitoring

Monitoring can be enabled and configured from **JavaFX → Settings → File Shield**. Every watched directory must be inside an approved scan root. UI changes restart the watcher immediately and survive backend restarts. For headless operation, configure it in `application.properties`:

```properties
ai-watchdog.file-shield.allowed-roots[0]=C:/Users/you/Downloads
ai-watchdog.file-shield.monitoring-enabled=true
ai-watchdog.file-shield.watch-directories[0]=C:/Users/you/Downloads
ai-watchdog.file-shield.recursive-monitoring=true
ai-watchdog.file-shield.max-monitoring-depth=5
ai-watchdog.file-shield.monitoring-worker-count=2
ai-watchdog.file-shield.monitoring-queue-capacity=128
ai-watchdog.file-shield.stability-check-interval-ms=250
ai-watchdog.file-shield.stability-check-attempts=6
```

The watcher observes create and modify events, waits for a file's size and modification time to stabilize, then calls the same read-only scan service used by the REST endpoints. Its worker count and queue are bounded; repeated pending events for a file are coalesced, and excess events are logged and dropped. A WatchService overflow triggers a bounded directory rescan. Symlinks and paths outside approved roots are skipped. Depth zero watches only the configured directory; higher values include that many levels below it. Invalid configuration values fail validation.

Results are published as Spring `FileShieldWatchResult` application events and written to the application log with the file name, event type, verdict, scan status, and SHA-256. No full local path is included in those result records. Manual unified assessments are persisted through the existing `security_events` history with reputation and optional PE evidence. See [THREAT_ASSESSMENTS.md](THREAT_ASSESSMENTS.md) for the data-preserving SQLite v2 migration and policy rules. WatchService events can be coalesced or missed by the operating system, so monitoring is best effort and does not replace a complete manual scan or endpoint protection.

The File Shield settings API is `GET/PUT /api/v1/file-shield/settings` and accepts loopback requests only. It reports whether the selected reputation database exists and has the expected `hash_reputation` columns. Choose a real database from a trusted source; the application does not seed reputation entries. An unavailable or invalid database continues to produce `LOOKUP_ERROR`; an unlisted hash in a readable database produces `UNKNOWN`.

JavaFX notification preferences are available from **Settings → Local Monitoring** and through loopback-only `GET/PUT /api/v1/notifications/preferences`. They persist independently at `%APPDATA%/AIWatchDog/notification-preferences.json` (or `~/.aiwatchdog/notification-preferences.json`). `enabled`, `warnEnabled`, and `blockEnabled` control only tray notifications; they do not change risk, policy, or audit behavior. The dashboard uses Spring/ML health and watcher state rather than a hardcoded “protection active” message.

Windows event telemetry, script monitoring, and process correlation are off by default and independently controlled in **Settings → Local Monitoring**. `GET/PUT /api/v1/windows-telemetry/settings` controls all three runtime switches; `GET /api/v1/windows-telemetry/health` returns collector/provider state and last-event timestamps. Settings persist to `%APPDATA%/AIWatchDog/windows-telemetry-settings.json`. Script static inspection uses the active backend File Shield roots; PowerShell event 4104 needs external Script Block Logging configuration; process events 4688/4689 need external Windows auditing and Security log read access. AI WatchDog never elevates, enables audit settings, or changes Defender policy. See [monitoring scope and event mapping](MONITORING.md#windows-defender-and-security-event-telemetry).
