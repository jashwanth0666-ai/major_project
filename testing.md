# AI WatchDog verification plan

**Status:** planned; not executed during implementation. This document is the single test plan for the repository. Run the procedures only in a disposable Windows account or VM with synthetic files and non-sensitive URLs. Record outcomes in the projectâ€™s normal issue or release process rather than editing this plan with unreviewed results.

## Prerequisites and safe environment

- Windows 10/11 VM or disposable workstation, standard (non-administrator) user, JDK 21 for Spring Boot, JDK 17+ for JavaFX, Maven, Python version and packages pinned in `requirements-api.txt`, and a Chromium browser if testing the extension.
- Start FastAPI and Spring Boot using `start-aiwatchdog.bat` or follow `doc/RUNNING.md`. Confirm service readiness through the documented `/health` endpoints before UI procedures.
- Use a temporary directory under the current user's profile, a copied test SQLite database, and benign generated text/script files. Do not use malware samples, live credentials, personal browsing history, production databases, or real user folders.
- Do not elevate the app. No requested procedure should change Defender, Firewall, UAC, audit policy, scheduled tasks, services, or startup registration.
- Keep the existing calibrated model and risk configuration unchanged. Do not compare or retrain model artifacts as part of these checks.
- A test is **PASS** only when every stated expected result occurs and no prohibited side effect occurs. Any mismatch, data loss, unauthorized action, or misleading health state is **FAIL**. Mark dependency-blocked cases **BLOCKED** with the missing provider/browser/OS capability; do not mark them passed.

## Unit and component cases

### U1 â€” URL inference and established risk mapping

- **Objective:** Confirm the existing Python model, calibration, threshold, Spring orchestration, and policy mappings remain intact.
- **Prerequisites:** Services ready; existing checked-in model artifact and configuration.
- **Procedure:** Submit a benign URL through `POST /api/v1/analyze`, then inspect the response and its persisted event. Compare the returned classification/risk/decision with the established threshold and policy contract in the project docs.
- **Expected:** Spring calls FastAPI; existing calibrated output and threshold `0.15` are preserved; policy remains SAFEâ†’ALLOW, LOW_RISKâ†’REVIEW, SUSPICIOUSâ†’WARN, HIGH_RISKâ†’BLOCK; audit output is sanitized according to current behavior.
- **Pass/fail:** PASS if the existing contract is unchanged and the audit row is present; FAIL if Java recalculates ML probability, risk mapping changes, or unsafe URL details are persisted contrary to policy.

### U2 â€” File Shield scanner and reputation lookup

- **Objective:** Verify safe hashing and distinct CLEAN, MALICIOUS, UNKNOWN, LOOKUP_ERROR, and scan-error semantics.
- **Prerequisites:** A temporary approved root; a benign text file; disposable SQLite copy with the documented `hash_reputation` schema.
- **Procedure:** Scan a file whose known SHA-256 has a verified test record; scan another file with no reputation row; scan with an invalid/missing database path; scan a file outside the approved root and a file exceeding the configured limit.
- **Expected:** Hashes are calculated without executing/modifying files. Known records map to their configured status; missing hashes in a readable DB return UNKNOWN; unavailable/malformed DB returns LOOKUP_ERROR; invalid paths/limits return a clear rejected/error state. No file is moved, changed, or deleted.
- **Pass/fail:** PASS if all cases preserve these distinctions and source files remain byte-identical; FAIL for false CLEAN on unavailable data, execution, mutation, or access outside approved roots.

### U3 â€” Static PE analyzer safety

- **Objective:** Ensure the optional PE analysis endpoint remains bounded and static.
- **Prerequisites:** Disposable approved root and a benign non-PE fixture plus a harmless test PE obtained from an internal build pipeline, if available.
- **Procedure:** Analyze the benign fixture and the approved test PE; attempt a path outside the root, a symlink escape, and an over-limit file.
- **Expected:** No analyzed file is executed; out-of-root and over-limit requests are rejected; a non-PE input is reported as unsupported/invalid; a PE result is explicitly described as heuristic evidence, not malware proof.
- **Pass/fail:** PASS if controls and wording hold; FAIL if a file executes or an unsigned/unfamiliar file is labeled malicious without known evidence.

### U4 â€” Monitor event rules, policy, and persistence

- **Objective:** Verify metadata findings route through the existing engines and shared policy.
- **Prerequisites:** Disposable SQLite database and backend available.
- **Procedure:** Submit synthetic FILE and PROCESS metadata events via `POST /api/monitor-events`, covering a benign text file name and documented suspicious suffix/utility names. Read them back through `GET /api/monitor-events` and inspect `monitor_events` in the copied DB.
- **Expected:** Findings include source/action/time, risk score/level, policy decision, and reasons; SQL values are parameterized; only allowed basename and numeric metadata are retained. The documented risk bands and policy mappings stay unchanged.
- **Pass/fail:** PASS if response and persisted row agree; FAIL if a heuristic is presented as a confirmed malware verdict, raw path/command line is collected, or a policy outcome is silently enforced at OS level.

### U5 â€” Settings validation and persistence

- **Objective:** Verify File Shield configuration is actually applied and persisted.
- **Prerequisites:** Spring Boot, test directories, and disposable `%APPDATA%` or user configuration directory.
- **Procedure:** Read `GET /api/v1/file-shield/settings`; update approved roots, watch roots, limits, database path, and monitoring desired state with `PUT`; read again; restart only in the later deployment test and read once more. Submit invalid roots, watch roots outside approved roots, invalid limits, and enabled monitoring with no roots.
- **Expected:** Valid settings are confirmed by the returned applied state and persisted in the per-user JSON configuration. Invalid requests return actionable errors and do not partially apply or persist.
- **Pass/fail:** PASS if read-after-write matches the accepted settings and invalid updates do not alter the prior state; FAIL if the UI claims an unapplied change succeeded.

### File Shield reputation and quarantine acceptance plan

- **Objective:** Verify metadata/signature reporting, provider degradation, explicit quarantine, and restore safely.
- **Prerequisites:** Windows disposable VM, approved test root, test-owned files with recorded hashes, isolated reputation SQLite copy, and a disabled or mock hash-only provider. Never use real malware.
- **Procedure:** Scan unsigned and signed benign fixtures individually and in a directory; compare SHA-256, metadata, signature state, and the directory `NOT_REQUESTED` signature message. Exercise local clean, malicious, suspicious, unknown, and unavailable DB/provider states. For quarantine, first attempt without confirmation, with unknown/clean reputation, with changed contents, a reparse-point path, and a path outside approved roots; then authorize a disposable known-malicious/suspicious fixture and verify it is moved into restricted storage. Restore it to a new approved destination, verify the hash and metadata, then retry with a destination collision.
- **Expected:** No file is executed or uploaded; only authorized known malicious/suspicious files are moved; unknown/unavailable status never authorizes quarantine. Hash identity and ACL failures do not mutate files. Restore refuses overwrites and verifies content. Each attempt that reaches operation start has durable correlated audit state; interrupted operations reconcile on restart without automatic movement.
- **Pass/fail:** PASS if operation responses and history agree with filesystem location, ACL, and hash; FAIL if policy display is mistaken for enforcement, a failure overwrites/moves a file, or an unknown reputation is treated as clean.
- **Execution status:** Planned only. Do not run this plan during implementation unless explicitly authorized.

### U6 â€” Notification preference policy

- **Objective:** Verify notification choices are persisted independently of scanner verdicts and remain local-only.
- **Prerequisites:** Spring Boot and JavaFX; disposable user configuration directory.
- **Procedure:** Read `GET /api/v1/notifications/preferences`; turn all notifications off from Settings and save; read the endpoint again; restart Spring only in the later lifecycle check and read the settings again; attempt a non-loopback update if a non-loopback client is available.
- **Expected:** UI uses the backend-confirmed values; WARN/BLOCK audit and policy records continue when notifications are disabled; preferences persist per user; non-loopback access is rejected.
- **Pass/fail:** PASS if notification visibility changes without changing analysis or policy; FAIL if preferences affect risk/audit results or the remote update succeeds.

### U7 â€” Windows event-to-policy mapping

- **Objective:** Verify the allowlisted Defender/Security event IDs use explicit source mappings into the existing risk bands and policy.
- **Prerequisites:** Unit test fixtures for `WindowsSecurityEvent`; no live event log changes.
- **Procedure:** Pass synthetic record metadata for Defender IDs 1116, 1117, 1118, 5007 and Security IDs 1102, 4697, 4698, 4719 into the analyzer. Include non-allowlisted IDs, malformed timestamps, and unsupported log names.
- **Expected:** Allowlisted records use the documented existing HIGH_RISK/SUSPICIOUS bands and shared policy outcomes, are persisted as `eventType=WINDOWS`, and contain only static reason text plus event record ID/provider. Unknown IDs are ignored. No formula recalculates URL risk or changes other engines.
- **Pass/fail:** PASS if every expected mapping and rejection holds; FAIL if raw event XML/message is retained, an unknown ID is promoted to a threat, or a BLOCK result is presented as enforced.

### U8 â€” Telemetry state and settings persistence

- **Objective:** Verify desired collector state is distinct from actual provider availability and persists safely.
- **Prerequisites:** Disposable user settings path and Windows environment; no need for Security log permissions.
- **Procedure:** Read `/api/v1/windows-telemetry/settings`; enable and disable with the loopback API; read settings and `/health` after each change; inspect provider states while the log is accessible and while access is denied/unavailable; restart backend and read saved state.
- **Expected:** Desired enablement and actual state are both returned. States distinguish DISABLED, UNSUPPORTED, STARTING, RUNNING, DEGRADED, and UNAVAILABLE as applicable. Errors use categories such as ACCESS_DENIED/LOG_DISABLED; provider event timestamps, drop counts, and restarts are not fabricated. Settings update is loopback-only and atomic.
- **Pass/fail:** PASS if returned state follows actual subscriptions and persists; FAIL if an inaccessible log is labeled active or non-loopback settings requests succeed.

## API contract checks

### A1 â€” Endpoint boundaries and response shapes

- **Objective:** Check documented URL, health, File Shield, settings, assessment, history, stats, and monitor-event contracts.
- **Prerequisites:** Spring and FastAPI running; test data only.
- **Procedure:** Exercise documented GET/POST/PUT methods with valid requests, malformed JSON, missing fields, invalid enum values, oversized input, and out-of-range limits. Call loopback-only settings operations from loopback and from a non-loopback test host when available.
- **Expected:** Successful calls return documented JSON; invalid input produces clear 4xx responses; service outages remain explicit; settings reject non-loopback access; history limits are bounded.
- **Pass/fail:** PASS if existing URL contracts remain compatible and rejection is explicit; FAIL on unintended 2xx, stack traces or secrets in responses, or externally reachable settings.

### A2 â€” Health and unavailable data states

- **Objective:** Ensure health and metrics reflect actual service/data availability.
- **Prerequisites:** Services running, plus the ability to stop/restart FastAPI in the disposable environment.
- **Procedure:** Read health with both services up; stop FastAPI and read health again; restore FastAPI; point a disposable frontend configuration at a stopped backend; temporarily make an optional history API unavailable.
- **Expected:** Spring and ML are reported independently. Dashboard stats and settings show unavailable/N/A or an error when the source fails, never fabricated zeros or an â€œall systems operationalâ€ claim.
- **Pass/fail:** PASS if each outage is explicit and recovery is reflected; FAIL if unavailable data is represented as a real empty count or active protection.

### A3 â€” Windows telemetry API and provider boundaries

- **Objective:** Check collector controls, provider status, and event ID filtering.
- **Prerequisites:** Windows backend with telemetry enabled in a disposable account.
- **Procedure:** Read the settings and health endpoints; submit valid enable/disable requests and malformed JSON; attempt non-loopback reads/updates; inspect the returned provider list and monitor-event history while waiting only for naturally occurring allowlisted events.
- **Expected:** Endpoints are loopback-only; the service reports each log/service independently; no existing log history is replayed at startup; only allowlisted event IDs enter monitor history.
- **Pass/fail:** PASS if contract and filtering match; FAIL if settings are remote-accessible, event contents outside the allowlist are ingested, or historical events are claimed as newly observed.

## File monitoring scenarios

### F1 â€” Event-driven configured-root observation

- **Objective:** Verify backend and desktop watchers observe only selected folders.
- **Prerequisites:** Two temporary folders, one configured as a watch root and one outside it; Settings and dashboard available.
- **Procedure:** Enable the backend watcher through Settings. Separately start desktop local monitoring with only the first folder selected. Create, modify, rename, and delete harmless files in each folder, including a nested directory up to the configured depth.
- **Expected:** Configured supported create/modify events arrive through the appropriate watcher and are visible in recent history; unconfigured files do not generate events. Rename recognition is treated as best effort. No file content is read by metadata-only monitoring.
- **Pass/fail:** PASS if observed events match enabled roots and labels/limitations are accurate; FAIL if monitoring silently expands to other folders or claims complete rename/delete coverage.

### F2 â€” Queue, overflow, locking, and recovery

- **Objective:** Exercise bounded callback handling and recoverable filesystem conditions.
- **Prerequisites:** Disposable folder; backend reachable and then temporarily unavailable; small configured queue if supported by the test profile.
- **Procedure:** Generate a controlled burst of harmless creates/modifies; hold one benign file open while changing it; temporarily stop Spring, generate events, restore Spring, and create another test event. Observe logs and watcher status.
- **Expected:** Filesystem callbacks remain responsive; access-denied/locked files and rejected queue work are reported or skipped without crashing the watcher; health reports outage and later recovery. No claim is made that dropped queue events were delivered.
- **Pass/fail:** PASS if the watcher survives and reports actual state; FAIL if it blocks indefinitely, crashes without health indication, or reports dropped events as stored.

### F3 â€” Symlink and path boundary

- **Objective:** Ensure watcher roots and recursive traversal do not escape approved roots through redirection.
- **Prerequisites:** Disposable approved root and a symlink/junction to a second temporary folder, where the OS permits creating it without elevation.
- **Procedure:** Configure the approved root and a redirected watch path; create a harmless file through the redirection; inspect watcher response and event history.
- **Expected:** Redirected roots/components are rejected or skipped; no outside file is scanned or reported.
- **Pass/fail:** PASS if no traversal crosses the approved boundary; FAIL if the outside target is watched. Mark BLOCKED if the OS account cannot create a test link.

## Process and script detection scenarios

### P1 — Existing Java process observer

- **Objective:** Measure the visibility and limits of Java `ProcessHandle` polling.
- **Prerequisites:** Non-admin Windows account and a harmless executable already installed.
- **Procedure:** Start and exit a benign process after monitoring starts; compare the process list with submitted events; repeat with the backend temporarily unavailable.
- **Expected:** Best-effort process starts within the polling interval; only exposed basename and PID are submitted. Parent chains, termination, signatures, and protected-process coverage come from the separate Windows collector where supported.
- **Pass/fail:** PASS if collected fields match the documented scope; FAIL if arbitrary processes are terminated or command lines are stored.

### P2 — Bounded script indicator analysis

- **Objective:** Verify static script-file and observed PowerShell script-block findings without executing test content.
- **Prerequisites:** Disposable Windows VM, script monitoring enabled, active approved File Shield watch root, and inert `.ps1`/`.bat` fixtures. Configure PowerShell Script Block Logging externally only if validating event 4104.
- **Procedure:** Add or modify harmless fixtures containing benign text and synthetic indicator patterns. Include a file above the 1 MiB cap and event text above the 32 KiB cap. Never invoke fixtures or generate malware. Inspect persisted reasons and confirm content and command lines are absent.
- **Expected:** Static findings identify `STATIC_SCRIPT_FILE`; event 4104 findings identify `OBSERVED_POWERSHELL_SCRIPT_BLOCK`; bounded or clean inputs do not create findings. Heuristic markers are evidence, not a malware verdict.
- **Pass/fail:** PASS if inputs remain unexecuted, bounds are enforced, only evidence labels persist, and sources are distinguishable; FAIL if content is persisted or a heuristic is presented as confirmed malware.

### P3 — Windows process correlation

- **Objective:** Check process creation/termination subscription, PID lifecycle, and suspicious parent-child correlations.
- **Prerequisites:** Disposable Windows VM with process monitoring enabled, Security log read access, externally configured Process Creation auditing, and harmless test executables.
- **Procedure:** Read provider state; wait for natural events or use synthetic analyzer fixtures for Office-to-script-host and script-host-to-utility chains. Verify termination removes PID state, duplicate records are suppressed, and stale/out-of-order records do not replace a newer PID instance. Do not change audit policy during the test.
- **Expected:** Events 4688/4689 are used only when present; command lines are inspected transiently and absent from persistence; only indicator combinations create findings; missing permission/audit data is reported without claiming complete coverage.
- **Pass/fail:** PASS if provider state, correlation, deduplication, and persisted summaries match; FAIL if command-line data is stored, events are fabricated, or missing telemetry is reported as clean.

The source-level unit cases for bounded script analysis and process correlation are in `backend/src/test/java/com/aiwatchdog/backend/windowstelemetry/ScriptThreatAnalyzerTest.java` and `ProcessBehaviorCorrelatorTest.java`. They cover script indicator detection, transient fragment assembly, unrelated process suppression, and duplicate event suppression. They are part of the backend test suite and still require execution in a later verification pass.
## Browser integration scenarios — planned, not executed

Prerequisites for manual cases: disposable Chrome or Chromium Edge profile, unpacked extension loaded with permissions granted, FastAPI and Spring running against a disposable database, and only benign controlled URLs. Use an approved phishing simulation URL only for BR4/BR6; never open live malware or a real credential link. Automated cases are source-level plans for `browser-extension/service-worker.test.cjs`, `backend/src/test/java/com/aiwatchdog/backend/service/AnalysisServiceTest.java`, and `backend/src/test/java/com/aiwatchdog/backend/controller/AnalyzeControllerTest.java`. No procedure below was run during this implementation.

### BR1 — Search ordinary words (`hi`, `hello`) — Manual + automated

- **Procedure:** Search each word on Google, Bing, and DuckDuckGo; inspect API requests and event history. Automated: verify search-page recognition and non-URL text rejection.
- **Expected:** Search page is labeled as such; no search terms or search-page URL are posted to `/analyze`; no URL audit event or high-risk notification is created from the query itself.

### BR2 — Direct visit to a legitimate website — Manual

- **Procedure:** Visit a controlled benign HTTP/HTTPS site, open the popup, then inspect the existing audit history.
- **Expected:** URL passes through `/api/v1/analyze`, current ML and policy fields/reasons appear, and one real navigation event is persisted. A green result appears only for `SAFE` plus `ALLOW` and is described as low risk, not a guarantee.

### BR3 — Mixed search-result destinations — Manual

- **Procedure:** View supported search result pages containing controlled destinations with differing known model/policy outcomes; scroll and allow dynamic results to render.
- **Expected:** At most eight unique links per batch get status badges with local check, warning, cross, or question-mark icons. Badge labels stay left-to-right on both LTR and RTL search pages. Ratings come from actual preview responses; preview calls do not create audit rows. Unavailable results are grey/unknown; no content beyond link targets is collected.

### BR4 — Approved phishing simulation URL — Manual

- **Procedure:** Use an approved, non-executing phishing test URL from the project owner’s authorized source; test as a search result preview and as a direct navigation.
- **Expected:** UI reflects the actual model/policy result. A preview is not persisted; direct navigation uses the normal persisted endpoint. Do not expect a specific verdict unless the current model actually returns it.

### BR5 — Unknown/new domain — Manual

- **Procedure:** Use a benign controlled newly registered or unfamiliar domain only if authorized; inspect popup and report.
- **Expected:** Display the actual available AI/policy result. No external reputation result is shown; missing/failed inference remains Unknown/unavailable, never Safe by default.

### BR6 — Confirmed dangerous destination and warning — Manual

- **Procedure:** Use an approved destination that the current service actually assesses as `HIGH_RISK` and policy `BLOCK`; observe current tab and repeat the navigation.
- **Expected:** Extension installs a dynamic `declarativeNetRequest` rule and shows a branded warning with safe host/reasons. The first request may begin loading before inference; subsequent matching navigations redirect before loading. If rule creation is unavailable, the UI states that honestly. BLOCK offers no proceed control.

### BR7 — Redirect chains and duplicate navigation — Manual + automated

- **Procedure:** Visit a benign site with a controlled redirect chain, activate and revisit its tab quickly; inspect persisted rows. Automated: exercise normalized URL and duplicate helper cases.
- **Expected:** Each actual destination is assessed when the browser reports its completed navigation, while activation duplicates in the short suppression window do not create duplicate calls. Redirects are not represented as a safe verdict for their source URL.

### BR8 — Unsupported schemes and browser-internal pages — Manual + automated

- **Procedure:** Visit `chrome://settings`, an extension page, `file://` and a harmless `data:` URL. Automated: verify sanitizer returns null for non-HTTP(S).
- **Expected:** No request or stale current-site assessment is shown for unsupported pages; no navigation rule is installed.

### BR9 — Backend unavailable or timeout — Manual

- **Procedure:** Stop Spring, then separately leave Spring up with FastAPI unavailable; navigate to a benign site and inspect popup health and assessment.
- **Expected:** No external fallback or fabricated verdict. Spring-down and Spring-up/ML-down states are distinguishable when `/api/v1/health` supplies both values; failed URL assessment is unavailable. A 12 second client timeout is bounded.

### BR10 — Dynamically updated result page — Manual

- **Procedure:** Load a supported results page, scroll to more results, and change the query using the search page controls.
- **Expected:** New eligible anchors receive at most one indicator per current href. Changed hrefs are re-rated; unrelated page elements remain unchanged; requests remain bounded and content collection is limited to hrefs.

### BR11 — Repeated warnings and notification deduplication — Manual

- **Procedure:** Repeat the same confirmed dangerous navigation and switch tabs around the redirect; separately perform a benign search repeatedly.
- **Expected:** The DNR rule redirects matching navigations consistently without loops. Ordinary queries and unvisited previews do not create persisted events or desktop notification spam. Actual distinct navigation events remain eligible for existing JavaFX notifications.

### BR12 — Sensitive query/path privacy — Manual + automated

- **Procedure:** Use synthetic credentials, query token, fragment, and opaque/sensitive path values; inspect request payloads, Spring logs/history, popup/report, and locally stored warning data. Automated: assert sanitizer removes these values.
- **Expected:** No credentials, query parameters, or fragment are submitted/displayed; likely sensitive paths are reduced to origin. Audit URL follows existing backend redaction. No raw page text is collected.

### BR13 — Protection disabled and reputation unavailable — Manual

- **Procedure:** Turn off the extension switch, revisit normal/result pages, confirm rules are removed; inspect popup capability notes.
- **Expected:** No new assessments or search ratings while paused; already injected result badges are removed; dynamic extension warning rules are removed; UI reports paused. Reputation provider, typo protection, and browser download scanning remain clearly unavailable rather than simulated.

### BR14 — Safe return and policy-controlled proceed — Manual

- **Procedure:** Trigger the warning from a controlled prior page and activate **Return to safety**; inspect warning controls for policy BLOCK.
- **Expected:** Return action does not send the user back into an automatic warning loop. A proceed action is not offered for BLOCK. Other policy decisions do not create dangerous-site interstitials under current behavior.

### Browser automated test plan

- `service-worker.test.cjs`: URL sanitization, search-page distinction, evidence-based warning gate, bounded preview requests, dynamic rule decisions, loopback-only outage behavior, and separate Spring/ML health states. Timeout behavior is covered by the manual BR9 procedure. Run later with `node --test browser-extension/service-worker.test.cjs`.
- `AnalysisServiceTest`: assert preview reuses ML/policy and never calls `SecurityEventLogger`.
- `AnalyzeControllerTest`: assert `/api/v1/analyze/preview` returns the existing response schema and delegates to `preview`.
- Browser extension manual procedures remain necessary for content-script selectors, Chrome/Edge permissions, dynamic DNR redirects, popup/report rendering, and safe return behavior.

## Permission and privilege checks

### S1 â€” Standard-user operation and loopback boundary

- **Objective:** Confirm the supported baseline does not require elevation and privileged settings remain local.
- **Prerequisites:** Standard Windows account, services started without Run as administrator, and a second machine or isolated non-loopback client if available.
- **Procedure:** Start monitoring, scan within approved roots, and use settings from the desktop as a standard user; attempt settings API access via a non-loopback interface.
- **Expected:** Supported user-level features work without elevation; the backend binds to loopback and settings reject remote callers. Missing filesystem permissions show unavailable/error, not active.
- **Pass/fail:** PASS if there is no silent elevation/system policy mutation; FAIL if a service, task, firewall rule, or security policy is installed/changed without explicit authorization.

### S2 â€” Path and request validation

- **Objective:** Check traversal, symlink, oversized request, and invalid path handling.
- **Prerequisites:** Disposable roots, temporary DB, and supported symlink/junction capability if available.
- **Procedure:** Submit traversal-like paths, out-of-root paths, redirected paths, nonexistent roots, oversized strings, malformed hashes, and invalid database paths through the corresponding documented endpoints.
- **Expected:** Requests fail safely; error messages are useful without exposing secrets or local file contents; no unintended path is scanned.
- **Pass/fail:** PASS if all rejected paths produce no side effect; FAIL if a path escape or unbounded request succeeds.

### S3 â€” Windows Security log permissions

- **Objective:** Verify Security and Defender provider availability without changing Windows permissions or policy.
- **Prerequisites:** Standard non-elevated Windows account; Security log read access may be unavailable by design.
- **Procedure:** Enable telemetry. Record actual state for Defender Operational, Security, and the Defender service. If Security returns ACCESS_DENIED, request that an administrator review access separately; do not add groups, elevate, or change log ACLs during this test. Recheck after the authorized OS owner grants read permission, if they choose to.
- **Expected:** Denied/disabled/missing providers are reported individually; another accessible provider may continue; app does not prompt for UAC or mutate auditing/Defender configuration.
- **Pass/fail:** PASS if actual limitations and permission categories are explicit; FAIL if permission is silently bypassed or a partial source set is called fully operational.

## Backend/UI switch synchronization

### C1 â€” Settings read/apply/refresh synchronization

- **Objective:** Verify UI switches reflect persisted and applied backend configuration.
- **Prerequisites:** JavaFX and Spring running; disposable test folders/database.
- **Procedure:** Open Settings, record loaded values and watcher state, change one setting, apply, reopen/refresh Settings, and inspect `GET /api/v1/file-shield/settings`. Repeat with backend disconnected during Apply.
- **Expected:** UI changes only to backend-confirmed state. Backend failure leaves prior displayed/applied values intact and shows an error. Desired monitoring state and actual `watcherActive` remain distinguishable.
- **Pass/fail:** PASS if UI and API converge on confirmed values; FAIL if a failed request shows success or the watcher is labeled active when it is not.

### C2 â€” Local monitor lifecycle controls

- **Objective:** Confirm dashboard control starts/stops the actual JavaFX file/process observers.
- **Prerequisites:** Backend available and one disposable local monitoring folder selected.
- **Procedure:** Start monitoring; create a harmless file and start a benign process; stop monitoring; repeat the events; inspect UI status and backend history.
- **Expected:** Start/stop affects the local observers; errors are visible if backend is unavailable; stopped observers do not continue submitting events. The control does not claim OS blocking.
- **Pass/fail:** PASS if state tracks running services and events; FAIL if status shows active after startup fails or a stop action leaves observers running.

### C3 â€” Windows telemetry switch and observed state

- **Objective:** Confirm the Settings control calls Spring and displays provider state rather than only its requested selection.
- **Prerequisites:** JavaFX and Spring on Windows; Security log access may be denied.
- **Procedure:** Open Settings â†’ Local Monitoring; record initial desired setting and actual status; enable collection and apply; observe each provider state; disable and apply; disconnect backend and try again.
- **Expected:** UI is disabled on unsupported OS, updates only after confirmed backend response, exposes provider errors and last-event timestamps, and distinguishes subscription from Defender service state. On backend failure, it reports unapplied state.
- **Pass/fail:** PASS if the UI matches the API's applied state; FAIL if selected-on is represented as active when providers fail.

## Tray and notification behavior

### T1 â€” Windows tray lifecycle

- **Objective:** Confirm hide, restore, alert navigation, and safe exit behavior.
- **Prerequisites:** Windows desktop session with notification area available; JavaFX and Spring running.
- **Procedure:** Start JavaFX, close the window, restore from tray, choose Inspect alerts, then choose Exit. Repeat on a system/session where tray support is unavailable if possible.
- **Expected:** When installed, window close hides the dashboard while already-started observers continue; Open restores it; Inspect alerts opens Threat Center; Exit closes observer threads and removes the icon. Without tray support, ordinary close exits cleanly.
- **Pass/fail:** PASS if lifecycle and cleanup match; FAIL if UI claims monitoring continues after process exit or the app cannot exit. Mark BLOCKED if no tray session is available.

### T2 â€” New-event notification and privacy

- **Objective:** Check deduplicated notifications from actual persisted events.
- **Prerequisites:** Tray supported; fresh test DB or known starting event IDs; backend available.
- **Procedure:** Start app and let its initial history baseline load; submit a synthetic event that maps to WARN/BLOCK; submit an ALLOW event; inspect tray and Activity history. Repeat with UI hidden.
- **Expected:** Only newly observed WARN/BLOCK records generate notifications; text contains source category, risk and decision only, no URL, path, process ID, command line, or content. Existing baseline rows do not replay.
- **Pass/fail:** PASS if notification source and text are accurate; FAIL if a notification is fabricated, sensitive details are exposed, or an ALLOW event is reported as a threat.

### T3 â€” Windows telemetry findings in dashboard and tray

- **Objective:** Verify allowlisted Windows findings use existing Activity/history/notification paths and policy labels do not claim enforcement.
- **Prerequisites:** Test database, Settings notification preferences, and injected `WindowsSecurityEvent` fixtures; tray may be unavailable in a headless session.
- **Procedure:** Feed a synthetic event fixture through the event analyzer, inspect `monitor_events`, Activity and Threat Center, then check tray notification text if supported. Do not cause Defender to detect a file or change a Windows policy to generate events.
- **Expected:** Source appears as Windows Security Event, event ID/record ID and source timestamp are retained through reasons, alert text contains no path/message/user data, and `BLOCK` is labeled as a policy outcome with no OS enforcement claim.
- **Pass/fail:** PASS if record and UI agree; FAIL if event content leaks or an audit decision is described as an enforced block. Mark tray portion BLOCKED when the OS session has no notification area.

## Collector failure and recovery

### R1 â€” Backend and ML service failure

- **Objective:** Verify independent health reporting and recovery.
- **Prerequisites:** Disposable environment with services under manual operator control.
- **Procedure:** Stop Spring while UI is open; restore it. Separately stop FastAPI while Spring remains up; restore it. Watch the dashboard health label, Settings status, and monitor submission behavior.
- **Expected:** Backend unavailable and ML unavailable are distinguished. Monitoring operations that need the backend report failure; the UI does not show all systems operational. After recovery, actual health and history return on refresh.
- **Pass/fail:** PASS if outage and recovery are observable without app crash or false success; FAIL if unavailable values are replaced with zero/active status.

### R2 â€” Watcher root removal and access loss

- **Objective:** Ensure inaccessible/deleted roots are reflected as degraded/unavailable.
- **Prerequisites:** Disposable configured root.
- **Procedure:** Enable monitoring; stop the watcher, rename/remove the test root or revoke access in the disposable environment, then query settings and inspect backend logs. Restore the folder and reapply configuration.
- **Expected:** Watcher status is not reported active when registrations are unavailable; errors are bounded and do not reveal contents; recovery requires a real restart/reconfiguration and is reflected when successful.
- **Pass/fail:** PASS if reported state follows actual watcher lifecycle; FAIL if failed registration is presented as monitoring.

### R3 â€” Windows event subscriber failure and recovery

- **Objective:** Check bounded restart behavior, provider-specific health, and event queue loss reporting.
- **Prerequisites:** Disposable Windows VM, telemetry enabled, and safe means to stop the collector-owned PowerShell process by stopping the backend (do not terminate unrelated PowerShell processes).
- **Procedure:** Stop Spring cleanly during a session; restart it; observe collector state and restart counter. If a test-only injected event source is available, saturate a bounded test queue; do not create Defender detections or change system audit policy.
- **Expected:** Backend shutdown releases the owned subscriber; startup recreates filtered subscriptions; failures show DEGRADED/UNAVAILABLE and bounded retry; drops are counted, not reported as stored events. Events during disabled/outage periods are documented as not backfilled.
- **Pass/fail:** PASS if owned resources recover and status is truthful; FAIL if orphan subscribers remain, retries grow without bound, or dropped data is reported complete.

## Quarantine and restoration

### Q1 â€” Policy is not OS enforcement

- **Objective:** Ensure a BLOCK policy decision never implies that a file was quarantined or blocked by Windows.
- **Prerequisites:** Current application build and disposable harmless file.
- **Procedure:** Submit a synthetic BLOCK policy event and verify the source file is unchanged. Separately inspect the File Shield action state for UNKNOWN, LOOKUP_ERROR, CLEAN, SUSPICIOUS, and known-malicious samples.
- **Expected:** A BLOCK policy event records only policy; quarantine appears only for current known-malicious/suspicious results and still requires a separate explicit confirmation and successful backend move.
- **Pass/fail:** PASS if policy does not change the file and UI only reports quarantine after backend success; FAIL if policy logging alone is presented as an OS block or quarantine.

### Q2 â€” Explicit quarantine and restoration workflow

- **Objective:** Verify the implemented manually confirmed quarantine/restore flow without malware or production files.
- **Prerequisites:** Windows disposable VM, approved test root, harmless fixture with synthetic known-malicious/suspicious DB row, test-only DB backup, and no active watcher on the fixture.
- **Procedure:** Follow the File Shield reputation and quarantine acceptance plan above. Exercise denied and successful operations, collisions, ACLs, hash changes, restore reinspection, and startup reconciliation.
- **Expected:** All moves require explicit confirmation; hash and ACL are verified; no overwrite/deletion occurs; audit state matches real file location; unknown/unavailable reputation does not authorize quarantine.
- **Pass/fail:** Planned only during implementation. PASS only after every Windows case is actually run and inspected; FAIL on any unrequested move, overwrite, false success, or audit mismatch.

## Security and privacy checks

### V1 â€” Data minimization and audit correctness

- **Objective:** Confirm persisted/UI/notification data do not include unnecessary sensitive values.
- **Prerequisites:** Disposable data store and synthetic URL/path strings containing fake tokens.
- **Procedure:** Send synthetic URL and monitor data, inspect SQLite rows, API responses, logs, UI history, and tray notifications. Inspect configured URL redaction and monitor request validation.
- **Expected:** URL inference receives its required input, but audit URL follows documented redaction; file/process monitor history uses basename and limited metadata; no file content, browser credentials, command lines, or real secrets are collected.
- **Pass/fail:** PASS if sensitive synthetic values are absent from surfaces where prohibited; FAIL if a secret is stored or surfaced unexpectedly.

### V2 â€” No execution or remediation

- **Objective:** Verify detections remain separate from actions and benign fixtures are never executed.
- **Prerequisites:** Harmless synthetic files and process names; disposable system.
- **Procedure:** Submit suspicious-looking names and inert script text only as data; inspect process list and filesystem before/after; submit policy WARN/BLOCK outcomes.
- **Expected:** No suspicious file/script runs, process is killed, network access is blocked, Defender/Firewall is changed, or source file is moved/deleted. Policy result remains an auditable recommendation/outcome only.
- **Pass/fail:** PASS if there is no such side effect; FAIL on any unauthorized execution or remediation.

## Performance and resource usage

### E1 â€” Bounded work and responsiveness

- **Objective:** Evaluate callback/UI responsiveness, queue bounds, and configured limits without treating measurements as universal guarantees.
- **Prerequisites:** Disposable VM, representative synthetic directory tree within configured maximums, and resource monitoring tools.
- **Procedure:** Observe idle and controlled file-event bursts; run a bounded directory scan; use a moderate synthetic process-start sequence. Record queue rejection/overflow, response latency, CPU, memory, and UI responsiveness. Do not use a whole drive or malware corpus.
- **Expected:** Directory scan respects file/depth/size bounds; filesystem callbacks avoid full scans inline; UI remains responsive; observed queue loss/errors are reported honestly. Record machine, workload, and values for later engineering review.
- **Pass/fail:** PASS against workload-specific limits agreed before the run; FAIL for unbounded growth, UI freeze, or silent loss reported as complete coverage. No performance target is assumed by this plan.

## Packaging and Windows startup

### D1 â€” Manual launch and dependency health

- **Objective:** Verify supported launch order and readable startup failures.
- **Prerequisites:** Clean disposable Windows user profile with documented Java, Maven, Python, and dependencies.
- **Procedure:** Launch using `start-aiwatchdog.bat`; separately follow `doc/RUNNING.md`; test missing FastAPI/backend executable only in the disposable profile; close all services normally.
- **Expected:** Launcher waits for health before dependent startup, reports timeout/failure, and does not silently install services or persistence. Manual start yields the same documented components.
- **Pass/fail:** PASS if startup and failure states are truthful and shutdown is clean; FAIL if a component reports ready before health succeeds.

### D2 â€” Optional start-at-login and Windows service gate

- **Objective:** Ensure persistence is not silently installed.
- **Prerequisites:** Standard user and clean disposable profile.
- **Procedure:** Inspect startup applications, scheduled tasks, and services before and after ordinary app use. Do not create or enable any of them for this check.
- **Expected:** Current project does not install a service or start-at-login entry. Any future installer must require explicit user action and document removal/permissions.
- **Pass/fail:** PASS if ordinary launch creates no persistence; FAIL if an entry appears without a user-approved installation step.

## End-to-end acceptance

### Z1 â€” Supported integrated vertical slice

- **Objective:** Confirm one real observation or URL reaches analysis, policy, persistence, JavaFX history, and (where supported) notification.
- **Prerequisites:** FastAPI model health verified, Spring available, JavaFX running, disposable SQLite DB, and local observers/extension installed only for the source being checked.
- **Procedure:** Submit one benign URL through the extension or UI; create one benign file under an explicitly watched folder; start one benign process; inspect API responses, URL and monitor history, database rows, dashboard, Activity, and tray behavior. Then stop each optional source and confirm its status changes.
- **Expected:** Existing URL ML and policy contract stays intact; monitor events use metadata heuristics; all persisted records are readable through Spring; JavaFX reflects returned values; only newly observed WARN/BLOCK events notify. ALLOW/unknown reputation remains distinct. No OS enforcement occurs.
- **Pass/fail:** PASS if every used source has an observable end-to-end path and unavailable integrations are labeled unavailable; FAIL if fake data, fabricated counts, false enforcement, or hidden source failures appear.

### Z2 â€” External capability inventory

- **Objective:** Make the remaining system boundary explicit at acceptance.
- **Prerequisites:** Completed Z1 and code/documentation review.
- **Procedure:** Record whether Chromium extension is installed; whether Defender/security event provider, digital-signature verification, script execution telemetry, threat-intelligence feed, quarantine service, network/process enforcement, notification-area support, and service installer are actually present and authorized.
- **Expected:** Documented implementation includes Windows Defender/Security telemetry where available, static script analysis, bounded process correlation, JavaFX tray notifications when supported, SHA-256 and single-file Authenticode inspection, local SQLite reputation, optional disabled-by-default HTTPS hash-only reputation, explicit restricted quarantine/restore, heuristic PE analysis, and Spring policy/audit. Unsupported providers and OS-level blocking are reported as unavailable/not implemented; policy BLOCK is not enforcement.
- **Pass/fail:** PASS if every capability claim maps to real code/provider and permission; FAIL if a dashboard label or policy decision implies an absent integration is operational.

### Z3 â€” Windows telemetry vertical slice

- **Objective:** Confirm native Windows event subscription â†’ backend analyzer â†’ shared policy â†’ existing SQLite history â†’ JavaFX display.
- **Prerequisites:** Windows 10/11, backend enabled through Settings, readable Defender Operational log, Security log access if authorized, JavaFX and Spring available.
- **Procedure:** Observe actual provider subscriptions and wait for naturally occurring allowlisted events. For deterministic pipeline coverage, separately use synthetic analyzer fixtures; do not change audit policies, generate Defender detections, or use malicious samples. Inspect provider status, `monitor_events`, Activity, and notification preferences.
- **Expected:** Provider status and last event times come from the real collector; only approved metadata is persisted; the existing Policy Engine receives source-specific mapped risk bands; any BLOCK outcome is clearly a recorded policy decision and does not claim an OS action.
- **Pass/fail:** PASS if live subscription and deterministic analyzer cases both meet their criteria; mark the live portion BLOCKED if the provider is missing/disabled or no natural event arrives. Do not label missing event traffic a pass or as zero detections.
