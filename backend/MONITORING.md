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

When the user starts protection from JavaFX, the application watches Downloads, Desktop, and Documents if those directories exist. To select different roots, set `AI_WATCHDOG_MONITOR_DIRS` to comma-separated directory paths before starting JavaFX. `AI_WATCHDOG_MONITOR_EXCLUDE` accepts comma-separated excluded paths. Watch registration includes subdirectories and newly created subdirectories. No admin privileges are required.

The monitor emits create and modify events. Same-directory delete/create pairs within two seconds are classified as probable renames. Rename detection depends on Windows WatchService events and can be missed. File sizes and names are metadata only; file content is never read.

## Process monitoring

Java `ProcessHandle` is polled every two seconds for new process IDs. `AI_WATCHDOG_PROCESS_POLL_MS` (or JVM property `aiwatchdog.process.poll-ms`) can set an interval from 1 to 60 seconds. Process names and IDs are sent; command-line arguments are not read. Some processes may not expose their executable name to a non-elevated process.

## Heuristic rules and policy

- Executable/script file suffixes receive a high risk score; macro-capable documents and disk images receive a suspicious score.
- Common dual-use Windows utilities receive a suspicious score based only on executable name.
- The shared policy mapping is retained: SAFE to ALLOW, LOW_RISK to REVIEW, SUSPICIOUS to WARN, HIGH_RISK to BLOCK.
- These are metadata heuristics, not malware detection. `BLOCK` is a recorded policy result; file access is not denied and processes are not terminated.

## Browser extension

The Chromium Manifest V3 extension is in `browser-extension/`. It observes active HTTP/HTTPS tab URLs, removes credentials, query strings, and fragments, and reduces sensitive or long opaque URL paths to `/`. It deduplicates for one minute and posts only to Spring on localhost. It does not read page contents or block navigation. The user must load the unpacked extension into Chrome or Edge; the project does not install it into a browser profile.
