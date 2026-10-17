# Browser, File, and Process Monitoring

## Current data flow

```text
Chromium extension / JavaFX file and process monitors
  -> Spring Boot monitor or analyze API
  -> File Engine / Process Engine or Python URL model
  -> Risk Engine
  -> Policy Engine
  -> SQLite audit records
  -> JavaFX history
```

The existing URL event table and API contract remain unchanged. File and process observations are stored in a separate `monitor_events` table in the same configured SQLite database.

## Monitor event API

`POST /api/monitor-events` accepts file or process metadata. `GET /api/monitor-events?limit=100` returns recent events. The limit is bounded to 1-500.

File example:

```json
{
  "eventType": "FILE",
  "action": "FILE_CREATED",
  "resourceName": "setup.exe",
  "processId": null,
  "sizeBytes": 512
}
```

Process example:

```json
{
  "eventType": "PROCESS",
  "action": "PROCESS_STARTED",
  "resourceName": "powershell.exe",
  "processId": 4812,
  "sizeBytes": null
}
```

Only a basename is accepted. Full local paths and process command-line arguments are not accepted or stored. SQL uses prepared statements.

## File monitoring configuration

When the user starts monitoring from JavaFX, only explicitly configured folders are watched. A clean install has no default watch roots; choose folders in Settings or set `AI_WATCHDOG_MONITOR_DIRS` to comma-separated paths before starting JavaFX. `AI_WATCHDOG_MONITOR_EXCLUDE` accepts comma-separated excluded paths. Watch registration includes subdirectories and newly created subdirectories. No admin privileges are required.

The desktop monitor emits create and modify events using metadata only. Same-directory delete/create pairs within two seconds are classified as probable renames. Rename detection depends on Windows WatchService events and can be missed. Separately, the opt-in backend script module below reads eligible script files from the existing configured File Shield roots under a strict size cap; it never executes them.

## Process monitoring

Java `ProcessHandle` is polled every two seconds for new process IDs. `AI_WATCHDOG_PROCESS_POLL_MS` (or JVM property `aiwatchdog.process.poll-ms`) can set an interval from 1 to 60 seconds. Process names and IDs are sent; command-line arguments are not read. Some processes may not expose their executable name to a non-elevated process.

## Heuristic rules and policy

- Executable/script file suffixes receive a high risk score; macro-capable documents and disk images receive a suspicious score.
- Common dual-use Windows utilities receive a suspicious score based only on executable name.
- The shared policy mapping is retained: SAFE to ALLOW, LOW_RISK to REVIEW, SUSPICIOUS to WARN, HIGH_RISK to BLOCK.
- These are metadata heuristics, not malware detection. `BLOCK` is a recorded policy result; file access is not denied and processes are not terminated.

## Browser extension

The Chromium Manifest V3 extension is in `browser-extension/`. It observes active HTTP/HTTPS tab URLs, removes credentials, query strings, and fragments, and reduces sensitive or long opaque URL paths to `/`. It deduplicates repeated observations and posts only to Spring on localhost with its scoped bearer token. It does not read page contents. After `HIGH_RISK` plus policy `BLOCK`, it can install a browser redirect warning for later matching navigations; the initial request can start before assessment completes. The user must load the unpacked extension into Chrome or Edge; the project does not install it into a browser profile.

## Desktop lifecycle and notifications

When the platform supports a system notification area, JavaFX installs an optional tray icon with **Open AI WatchDog**, **Inspect alerts**, and **Exit** actions. Closing the dashboard window hides it while the JavaFX process and any already-started desktop observers remain alive. Choosing **Exit** shuts the observers down. If the OS has no usable tray, the app follows the normal close behavior. The app does not configure start-at-login or install a Windows service.

The dashboard protection indicator reads Spring/ML health and the backend File Shield watcher's reported active state. `WARN` and `BLOCK` notifications are emitted only for newly observed persisted URL or monitor events after the initial history snapshot. Notification text excludes URLs, paths, process IDs, command lines, and file contents. The initial snapshot is a baseline; a reconnect can miss events older than the backend's bounded recent-history response. These policy decisions are audit outcomes and do not enforce Windows access control.

Notification preferences are read and updated through loopback-only `GET/PUT /api/v1/notifications/preferences`. The JSON fields are `enabled`, `warnEnabled`, and `blockEnabled`; defaults enable WARN and BLOCK notifications. Spring persists them to `%APPDATA%/AIWatchDog/notification-preferences.json` (or `~/.aiwatchdog/notification-preferences.json` when APPDATA is unavailable). JavaFX applies only the confirmed response and reads the preferences again as part of backend status refresh. The notification area itself is optional; unsupported/headless sessions cannot display tray messages.

The JavaFX desktop observers use Java NIO `WatchService` and `ProcessHandle` polling. `ProcessHandle` reports best-effort starts but does not provide parent chains, command lines, signatures, memory telemetry, or complete process start/stop coverage. Optional Windows event subscriptions below add only the providers and fields explicitly enabled. Browser URL observations require the separately installed Chromium extension. Each source reports only its own observed availability and coverage.

## Windows Defender and Security event telemetry

The optional Spring collector uses Windows `EventLogWatcher` subscriptions through a fixed, packaged PowerShell script. Three independent settings are available under **Settings → Local Monitoring**: Defender/Security telemetry, script monitoring, and process correlation. They default off and persist under `%APPDATA%/AIWatchDog/windows-telemetry-settings.json` (or `~/.aiwatchdog/` when APPDATA is unavailable). The collector never enables audit categories, changes Defender settings, executes script content, or requests elevation.

Loopback-only APIs:

- `GET /api/v1/windows-telemetry/settings` reports desired enablement and observed collector/provider state.
- `PUT /api/v1/windows-telemetry/settings` accepts any of `{"enabled":true|false,"scriptMonitoringEnabled":true|false,"processMonitoringEnabled":true|false}` and applies the supplied settings immediately. The three settings are independently persisted.
- `GET /api/v1/windows-telemetry/health` reports collector state, provider states, errors, timestamps of the latest received matching event, queue drops, and restart count.

The collector subscribes only to these event IDs:

| Log | Event IDs | Policy interpretation in this app |
| --- | --- | --- |
| Defender Operational | 1116 detection, 1117 action reported, 1118 action failed | Existing HIGH_RISK band and BLOCK policy outcome |
| Defender Operational | 5007 configuration changed | Existing SUSPICIOUS band and WARN policy outcome |
| Security | 1102 audit log cleared | Existing HIGH_RISK band and BLOCK policy outcome |
| Security | 4697 service installed, 4698 scheduled task created, 4719 audit policy changed | Existing SUSPICIOUS band and WARN policy outcome |
| PowerShell Operational | 4104 script block | Static rule evidence from bounded transient script text; `eventType=SCRIPT`, WARN policy outcome |
| Security | 4688 process creation, 4689 process termination | Parent/child correlation; only suspicious combinations become `eventType=PROCESS` findings |

### Script analysis

When script monitoring is on, the collector subscribes to PowerShell Operational event 4104. PowerShell Script Block Logging must already be enabled by the system administrator; a successful log subscription alone cannot guarantee that Windows will generate these events. Microsoft documents event 4104 in [PowerShell logging](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging?view=powershell-5.1) and recommends Protected Event Logging to protect logged script content. AI WatchDog inspects text transiently, limited to 32 KiB per event. The backend File Shield watcher also inspects created/modified `.ps1`, `.psm1`, `.psd1`, `.bat`, `.cmd`, `.vbs`, `.vbe`, `.js`, `.jse`, `.wsf`, and `.hta` files under its configured, approved watch roots. Static file reads are capped at 1 MiB and occur on the existing bounded worker pool. Scripts are never executed. Persisted evidence contains only rule names, timestamp, source, a safe basename, and policy result; script content and command lines are not persisted.

Rules identify encoded content, download-and-execute combinations, script/persistence patterns, suspicious utility combinations, process-injection API combinations, high-complexity obfuscation patterns, and markers associated with known offensive tools. These are heuristic indicators and may be false positives; the known-tool markers are not a threat-intelligence feed or a malware verdict. Static file findings (`STATIC_SCRIPT_FILE`) are distinguished from observed PowerShell script blocks (`OBSERVED_POWERSHELL_SCRIPT_BLOCK`). Static analysis is unavailable until backend File Shield folder monitoring is active.

### Process correlation

When process monitoring is on, the collector subscribes to Security events 4688 and 4689. Microsoft documents [4688 process creation](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688) and [process creation audit policy](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-process-creation). Process Creation auditing must be configured externally; the application does not change audit policy. The collector reads process and parent names/PIDs and may inspect an available 4688 command line transiently for script indicators. Command-line event logging is separately configurable and can expose secrets in the Windows Security log; this feature does not require it. AI WatchDog does not persist the command line or full executable path. An in-memory, bounded 30-minute process cache correlates parent-child names, deduplicates event record identities, ignores stale PID replacements, and removes exited processes from the cache. Only combinations such as an Office parent starting a script host, a script host starting a dual-use utility, or script rule matches are persisted. This source is incomplete when audit records omit parent or command-line data and is not a complete process monitor.

These are fixed source-to-existing-risk-band mappings, not a new unified risk formula. A Security/Defender `BLOCK` is an AI WatchDog policy record; this application does not enforce an OS block or perform Defender remediation. An event by itself is not a complete incident assessment. Microsoft documents [Defender event 1116](https://learn.microsoft.com/en-us/defender-endpoint/mde-demonstration-amsi), [scheduled task event 4698](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4698), and the semantics of the [.NET EventLogWatcher subscription](https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.eventing.reader.eventlogwatcher).

Security findings enter the existing `MonitorEventAnalyzer`, `PolicyEngine`, and `monitor_events` table with their event type, action, timestamp, basename-safe resource, evidence summary, and policy outcome. Script and process command-line/content fields are used only transiently by the analyzer and are not persisted or logged. Activity shows the evidence summary and source. Settings displays each provider's state, permission/error category, latest matching event, and collector counters. All `BLOCK` values remain policy audit decisions; no OS enforcement or Defender remediation is performed.

Security log read access varies by Windows policy and may require an administrator to grant a local read permission (for example through the Event Log Readers group). AI WatchDog does not grant that permission or prompt for UAC. Defender log subscription can be unavailable if the component/log is disabled or managed by another antivirus product. `SUBSCRIBED` means the filtered event subscription started; it does not prove that auditing is configured to generate events. New events are subscribed from the time monitoring is enabled; history produced while disabled or while the collector is unavailable is not backfilled. PowerShell/Event Log provider failures appear as provider states such as `ACCESS_DENIED`, `LOG_DISABLED`, or `UNAVAILABLE`; partial access is `DEGRADED`, not healthy.

### File inspection, reputation, and quarantine

File Shield computes SHA-256 with bounded streaming and captures file size, extension, creation/modification times, and file identity consistency. Single-file scans request Windows Authenticode inspection through a fixed, non-interactive PowerShell command; file content is not executed or uploaded. Directory and continuous watcher scans intentionally skip signature inspection to avoid launching one PowerShell process per file. Signature outcomes are `VALID`, `INVALID`, `UNSIGNED`, `INSPECTION_ERROR`, `UNSUPPORTED`, or `NOT_REQUESTED`; unsigned files are not automatically malicious.

The local SQLite hash reputation remains authoritative for known local records. An optional hash-only provider is disabled by default and can be configured with `AI_WATCHDOG_THREAT_INTEL_ENABLED`, `AI_WATCHDOG_THREAT_INTEL_ENDPOINT` (HTTPS only), and `AI_WATCHDOG_THREAT_INTEL_API_KEY`. It sends only the SHA-256 digest, enforces configured timeout/rate/cache bounds, and exposes provider state in File Shield Settings. Never put provider secrets in screenshots, logs, or checked-in configuration. `UNKNOWN` means no verdict was returned; it does not mean clean.

Quarantine is a manual operation available only for a current `KNOWN_MALICIOUS` or `SUSPICIOUS` reputation result. The desktop asks for confirmation and submits the scanned path plus expected hash; the backend rechecks hash, identity, approved-root membership, and Windows reparse points before a same-volume filesystem move. Storage is under `.aiwatchdog-quarantine` in the approved root and receives a restrictive owner/SYSTEM ACL. Cross-volume moves, collisions, changed files, unsupported ACLs, and unavailable reputation fail closed. The backend never auto-quarantines from watcher events or policy decisions. Restore requires separate confirmation, an approved destination, a non-existing destination path, and matching SHA-256; the UI lets the user choose an approved folder. Reinspection is optional; when enabled it permits restoration only for a known-clean hash, while unknown/unavailable/malicious outcomes remain quarantined unless the user explicitly opts out. Operations are persisted in the existing `security_events` table as `FILE_SHIELD_OPERATION` records with `correlation_id`; no schema migration is needed. Startup recovery only reconciles file location and hashes and never performs an unrequested move.
