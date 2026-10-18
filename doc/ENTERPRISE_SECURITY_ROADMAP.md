# AI WatchDog enterprise security roadmap

## Purpose and current product boundary

AI WatchDog is a local Windows monitoring prototype. This roadmap describes a staged path for improving it; it does not claim feature parity with CrowdStrike, SentinelOne, Microsoft Defender, Safe Browsing, or SmartScreen. Kernel drivers, fleet management, malware prevention, and a continuously operated threat-intelligence service require dedicated engineering, operations, and independent security review.

The current checked-in source already implements a limited subset of several items in the gap list:

| Area | Current implementation | Remaining gap |
|---|---|---|
| OS enforcement | URL policy decisions are recorded. The browser extension can add a Chromium redirect warning after `HIGH_RISK` plus `BLOCK`. | No kernel enforcement; the first browser request can start before analysis; URL WARN/REVIEW does not block. File/process monitor decisions do not enforce OS policy. |
| File inspection | File Shield calculates SHA-256, inspects file metadata/signatures, checks configured local reputation, and has explicitly confirmed quarantine for known malicious/suspicious reputation. FastAPI includes bounded static PE heuristics. | No general content scanning engine, YARA rules, sandbox, or automated behavior analysis. Extension downloads are not inspected. |
| Endpoint telemetry | Optional Windows Defender/Security/PowerShell telemetry and process correlation exist; Java and Spring also have best-effort user-space file/process observers. | No kernel telemetry, memory scanning, network flow collection, lateral-movement analytics, threat hunting, or fleet correlation. |
| Reputation | Local hash database is supported; optional HTTPS hash-only provider is configurable. | No URL/domain reputation provider, URL feed ingestion, or managed feed update service. |
| Response | User-confirmed, integrity-checked file quarantine and restore are implemented for eligible files. Browser warning redirects can be installed for a URL decision. | No process termination, host isolation, automatic remediation, or centrally approved response workflow. |
| API security | Spring and FastAPI default to loopback; several administrative routes check the remote address. | No general authentication/authorization model; not every route has a local-address guard. Loopback alone does not authenticate local processes or defend every browser-origin scenario. |
| Operations | Local SQLite history, JavaFX dashboard, local notifications, health state, and bounded provider status exist. | No durable remote event export, SIEM integration, SOC/fleet console, enrollment, or central policy distribution. |
| URL phishing assessment | A fixed 25-feature calibrated XGBoost artifact, threshold `0.15`, risk bands, optional hostname reputation, and explainable hostname heuristics are used. Extension can redirect later visits after a BLOCK result. | No page DOM/content, DNS/WHOIS, certificate, redirect-chain, visual brand, form, adaptive calibration, or continuous model update analysis. Hostname heuristics are partial and do not cover general visual similarity. Explanations are heuristic indicators, not model attribution. |

## Prioritized phases

### Phase 0 — Define the supported security boundary and deployment profile

**Priority: immediate; prerequisite for every other phase.**

- Keep the default product local-only and user-space. Define supported Windows versions, privilege level, data retention, supported browser versions, and explicit non-goals.
- Remove developer-account-specific filesystem paths from checked-in runtime configuration. Resolve roots from user configuration or require explicit settings; reject missing roots with an unavailable/configuration state.
- Document data flows, local ports, file permissions, telemetry contents, provider timeouts, and behavior when each dependency is unavailable.
- Keep monitoring, external providers, telemetry collection, and any response action opt-in with visible applied state.

**Acceptance gate:** a clean user profile starts with no developer-specific paths; an unset path does not scan an unintended directory; provider outage is visible and never represented as a clean verdict; docs accurately distinguish observed, inferred, and enforced behavior.

### Phase 1 — Secure the local control plane

**Priority: highest engineering priority.**

- Inventory every Spring and FastAPI route by sensitivity (read-only assessment, settings, file path access, quarantine/restore, telemetry control, health) and classify required callers.
- Add a local-client authorization design for the desktop app, extension, and Spring-to-FastAPI calls. Define credential creation, storage, rotation, revocation, and recovery before adding enforcement. Avoid embedding a shared static token in extension source or a checked-in config file.
- Apply authorization consistently, including scan and policy routes; retain loopback binding and explicit origin handling as defense in depth. Treat CORS as a browser boundary, not authentication.
- Restrict administrative operations to the intended local user and require explicit confirmation for destructive/reversible actions. Add audit records for rejected administrative attempts without storing credentials.
- Set request size/time limits and safe error responses for all externally reachable routes.

**Acceptance gate:** unauthenticated requests cannot read or mutate protected state; only the intended local client can call protected operations; invalid/expired credentials fail closed; service-to-service failure is visible; no secret appears in logs, extension source, responses, or the repository. Validate browser and desktop flows under the selected credential provisioning model before release.

### Phase 2 — Improve URL assessment with bounded, optional evidence

**Priority: high; after control-plane and privacy design.**

- Preserve the current model, calibration, feature order, and threshold until a labeled evaluation demonstrates a justified change. First establish a reproducible false-positive/false-negative evaluation with time and domain splits and reviewed labels.
- Add an optional URL/domain reputation interface with explicit provider provenance, timestamp, cache age, timeout, quota handling, and `UNKNOWN`/`UNAVAILABLE` states. Never turn missing reputation into a clean result.
- Start with origin/URL reputation or safe DNS metadata lookups; send the minimum URL data necessary, redact query/fragment values, require explicit opt-in, and make provider selection/configuration visible.
- Treat DNS, WHOIS/domain age, TLS certificate, redirects, and page-derived signals as separate evidence with source and observation time. Do not claim redirect destinations were checked unless actually observed. Avoid fetching arbitrary pages server-side; protect against SSRF and unsafe content handling if page retrieval is later proposed.
- Add typo/homograph and deceptive-host detection as explainable suspicion signals with controlled tests. Do not introduce blanket popular-domain allowlists.
- Keep heuristic explanation reasons separate from model attribution. Add true attribution only if the model/tooling supports it and calibration is not misrepresented.

**Acceptance gate:** every result identifies which evidence was available and stale/unavailable sources; preview and visit paths share the same assessment semantics; a provider timeout cannot lower risk; adversarial lookalikes are not trusted by brand substring; offline mode remains explicit.

### Phase 3 — Strengthen endpoint visibility and file inspection

**Priority: medium-high; retain user-space deployment first.**

- Improve reliability reporting for existing WatchService, Windows Event Log, and process-correlation sources: dropped counts, coverage, queue saturation, restart state, and missing permissions must be visible.
- Add content scanning only through a maintained, licensed scanning engine or a clearly bounded local signature/YARA integration. Keep the existing static PE heuristic labeled as heuristic. Never execute a sample as part of ordinary scanning.
- Add controlled, opt-in scan-on-observation only after load, privacy, file-locking, false-positive, and quarantine/restore behavior are specified. Unknown scan results must not be treated as clean or eligible for quarantine.
- Expand process and file evidence correlation with durable event identity, bounded retention, and source timestamps before adding automated actions.

**Acceptance gate:** coverage gaps and dropped observations are measurable; scans are bounded and non-executing; known/unknown/error reputation remains distinct; quarantine remains explicit, integrity-checked, reversible, and audited.

### Phase 4 — Response controls with user approval

**Priority: medium; depends on reliable evidence and authorization.**

- Provide a response preview: triggering evidence, scope, affected process/file/URL, reversibility, and rollback path.
- Add process termination or network isolation only as a separate, explicitly confirmed action with race-resistant identity checks and durable audit. Do not terminate from a filename or model score alone.
- Keep automatic response disabled by default. Any future policy automation needs staged observe-only/shadow mode, allowlisted test fixtures, rollback controls, and per-action safeguards.
- Make browser installation/update and rule state transparent. Preserve the distinction between a warning decision, an installed browser redirect rule, and prevention of the initial request.

**Acceptance gate:** rejected/stale evidence cannot trigger action; user confirmation binds to the current file/process identity; each operation can be reconciled after interruption; audit failure behavior is defined; rollback is documented and exercised in an isolated environment.

### Phase 5 — Operational export and managed deployment

**Priority: later; requires an operator and service model.**

- Define a versioned event export schema and delivery guarantees before SIEM connectors. Add signed/authenticated outbound transport, retry/backoff, buffering limits, data minimization, and operator-visible delivery state.
- Build fleet enrollment, device identity, policy distribution, update signing, key rotation, revocation, and support lifecycle before a central dashboard.
- Add connectors one at a time against a test tenant; do not silently export URLs, local paths, process details, or file hashes.
- Provide retention/deletion, tenant isolation, administrator roles, and incident response procedures for any hosted service.

**Acceptance gate:** no event is reported delivered until acknowledged; queue loss is observable; tenant isolation and authorization are reviewed; export can be disabled and buffered data handled according to policy.

### Phase 6 — Evaluate kernel-level protection as a separate product track

**Priority: defer.**

- A file-system minifilter or endpoint driver is not a small extension of Java `WatchService`. It requires Windows driver signing, installation/update/uninstall, crash safety, compatibility testing, kernel security review, and a tested recovery path.
- Do not add a driver until a supported deployment owner, signing pipeline, threat model, incident response, and maintenance commitment exist. Keep the user-space prototype separate from any driver package.

**Acceptance gate:** independent driver threat review, signed release pipeline, supported OS matrix, failure/recovery tests, uninstall/recovery plan, and explicit operator authorization are complete before pilot deployment.

## Phishing-specific evaluation track

Phishing protection is a separate quality and data-governance effort, not a single feature patch. Establish a labeled benchmark with timestamped URLs, domain-separated and time-separated splits, approved sources, label provenance, duplicate/conflict review, false-positive cost, and aging/retention policy. Report precision, recall, false-positive rate, calibration, coverage, and confidence intervals for both the existing model and every added signal. Keep threshold selection separate from the enterprise roadmap and do not tune from one known-good URL.

Browser page inspection, form detection, visual brand similarity, and redirect analysis require a privacy review and browser-specific design. Collect only the minimum signals needed, do not read credentials or form values, and ensure any page retrieval or screenshot analysis is isolated from arbitrary active content. External reputation and certificate/DNS checks must include provenance and unavailability semantics. A model update pipeline needs signed artifacts, offline evaluation, staged rollout, rollback, and versioned calibration metadata before deployment.

## First implementation slice

The first source slice now covers **Phase 0 plus local control-plane authentication from Phase 1**:

- Removed developer-specific scan/watch root defaults. Clean installs begin with no approved scan roots and monitoring disabled until configured.
- Added a per-user credential initializer with three random 256-bit tokens, Windows ACL restriction for the default credential directory/file, and explicit rotation.
- Added a Spring bearer-token filter on all routes except public `GET /api/v1/health`. The extension token is limited to unified URL assessment and preview; desktop token accesses normal application routes.
- Added a separate Spring-to-FastAPI credential for inference and PE analysis. Spring health now performs an authenticated FastAPI `/auth-check`.
- Added a browser extension Options page to store the extension token in extension storage.
- Routed browser navigation and unvisited-result preview through the same unified assessment service. Only actual navigation writes the assessment audit event; the extension token is scoped to those two URL endpoints.

This is not per-process Windows identity: same-account processes can generally read the user's token file. The token system reduces unauthenticated/browser-origin access and limits the extension role; it does not defend against a compromised local account. Manual user testing remains pending. No tests or application runs were performed during implementation.
## Source map

- URL ML and feature pipeline: `api/server.py`, `api/inference/detector.py`, `ml_model/phase4/risk_engine_config.json`.
- URL policy and API orchestration: `backend/src/main/java/com/aiwatchdog/backend/service/AnalysisService.java`, `backend/src/main/java/com/aiwatchdog/backend/policy/PolicyEngineImpl.java`, `backend/src/main/java/com/aiwatchdog/backend/controller/AnalyzeController.java`.
- Browser assessment and redirect rules: `browser-extension/service-worker.js`, `browser-extension/README.md`.
- File inspection, reputation, and quarantine: `backend/src/main/java/com/aiwatchdog/backend/fileshield/`, `api/pe_analyzer/`.
- Windows telemetry and heuristic event handling: `backend/src/main/java/com/aiwatchdog/backend/windowstelemetry/`, `backend/src/main/java/com/aiwatchdog/backend/monitor/`.
- User-space file observation: `Frontend/src/main/java/com/aiwatchdog/service/FileSystemMonitorService.java`.
- Runtime defaults needing portability review: `backend/src/main/resources/application.properties`.

## Status

This roadmap is based on source inspection. The first Phase 0/1 source slice and initial Phase 2 slices are implemented but await manual validation: an opt-in hostname reputation connector, explainable local hostname heuristics, unified evidence semantics for browser navigation and preview, operator-configured exact-host domain rules, and a reproducible evaluator for the frozen model. The evaluator reports full held-out/domain-split results, model hash, calibration metrics, per-domain review summaries, and manual false-positive/false-negative adjudication queues. Temporal evaluation remains unavailable because reliable timestamps are absent. The evaluator does not train or alter thresholds. Remaining Phase 2 work and Phases 3–6 remain roadmap work. No tests, builds, benchmarks, validation commands, model evaluation, or application runs were performed during this development turn.

The desktop observer reliability slice now exposes WatchService coverage, overflow events, registration failures, failed uploads, dropped uploads, and queue depth. Process polling now exposes observed process count, detected starts, metadata access and polling failures, failed uploads, dropped uploads, and queue depth. Dashboard status is marked degraded when either source reports errors. These remain user-space, best-effort observers: they do not provide kernel coverage, process memory inspection, event delivery guarantees, or prevention. Manual testing is pending.
