package com.aiwatchdog.backend.monitor;

import com.aiwatchdog.backend.windowstelemetry.WindowsSecurityEvent;
import com.aiwatchdog.backend.windowstelemetry.ProcessBehaviorCorrelator;
import com.aiwatchdog.backend.windowstelemetry.ScriptThreatAnalyzer;
import com.aiwatchdog.backend.policy.Decision;
import com.aiwatchdog.backend.policy.PolicyEngine;
import com.aiwatchdog.backend.fileshield.dto.FileScanResponse;
import org.springframework.stereotype.Service;
import java.time.Instant;
import java.util.List;
import java.util.Locale;

@Service
public class MonitorEventAnalyzer {
    private final FileEngine fileEngine;
    private final ProcessEngine processEngine;
    private final HeuristicRiskEngine riskEngine;
    private final PolicyEngine policyEngine;
    private final MonitorEventRepository repository;

    public MonitorEventAnalyzer(FileEngine fileEngine, ProcessEngine processEngine,
                                HeuristicRiskEngine riskEngine, PolicyEngine policyEngine,
                                MonitorEventRepository repository) {
        this.fileEngine = fileEngine;
        this.processEngine = processEngine;
        this.riskEngine = riskEngine;
        this.policyEngine = policyEngine;
        this.repository = repository;
    }

    public MonitorEventResult analyze(MonitorEventRequest request) {
        String type = canonical(request.eventType());
        AnalysisSignals signals = switch (type) {
            case "FILE" -> fileEngine.analyze(request);
            case "PROCESS" -> processEngine.analyze(request);
            default -> throw new IllegalArgumentException("event_type must be FILE or PROCESS");
        };
        RiskAssessment risk = riskEngine.assess(signals);
        String resource = request.resourceName().trim();
        Decision decision = policyEngine.evaluateRiskLevel(risk.level());
        MonitorEventResult event = new MonitorEventResult(null, Instant.now(), type,
                canonical(request.action()), resource, request.processId(), request.sizeBytes(),
                risk.score(), risk.level().name(), decision.name(), risk.reasons());
        return repository.save(event);
    }

    /** Maps documented Windows event IDs to existing risk bands; this is not an OS enforcement action. */
    public MonitorEventResult analyzeWindowsEvent(WindowsSecurityEvent event) {
        WindowsEventRule rule = windowsRule(event);
        if (rule == null) return null;
        String provider = event.logName().contains("Defender") ? "Microsoft Defender" : "Windows Security";
        String resource = provider + " event " + event.eventId();
        List<String> reasons = List.of(rule.reason(), "Event record " + event.recordId()
                + " from " + provider + "; review the original Windows event for full context.");
        RiskAssessment risk = riskEngine.assess(new AnalysisSignals(rule.score(), reasons));
        Decision decision = policyEngine.evaluateRiskLevel(risk.level());
        MonitorEventResult finding = new MonitorEventResult(null,
                event.timestamp() == null ? Instant.now() : event.timestamp(), "WINDOWS",
                rule.action(), resource, null, null, risk.score(), risk.level().name(), decision.name(), risk.reasons());
        return repository.save(finding);
    }

    public MonitorEventResult recordScriptFinding(String resourceName, ScriptThreatAnalyzer.ScriptAnalysis analysis) {
        return recordScriptFinding(resourceName, analysis, null);
    }

    public MonitorEventResult recordScriptFinding(String resourceName, ScriptThreatAnalyzer.ScriptAnalysis analysis, Long processId) {
        if (analysis == null || analysis.evidence().isEmpty()) return null;
        return recordFinding(analysis.observedAt(), "SCRIPT", analysis.source(), safeBasename(resourceName),
                processId, analysis.score(), analysis.evidence().stream().map(rule -> "Static or observed script indicator: " + rule).toList());
    }

    public MonitorEventResult recordProcessFinding(ProcessBehaviorCorrelator.ProcessFinding finding) {
        if (finding == null) return null;
        return recordFinding(finding.timestamp(), "PROCESS", "PROCESS_BEHAVIOR_CORRELATION",
                finding.processName(), finding.processId(), 72,
                List.of(finding.evidence(), finding.parentSummary(),
                        "Correlated metadata only; command-line content is not retained."));
    }

    /** Records scan evidence while keeping reputation, signature, risk, and policy outcomes distinct. */
    public MonitorEventResult recordFileInspection(FileScanResponse result) {
        if (result == null || result.sha256() == null) return null;
        int score = switch (result.reputationStatus()) {
            case KNOWN_MALICIOUS -> 90;
            case SUSPICIOUS -> 60;
            case UNKNOWN, LOOKUP_ERROR -> 35;
            case KNOWN_CLEAN -> 0;
        };
        if ("INVALID".equalsIgnoreCase(result.signatureStatus()) && score < 60) score = 60;
        List<String> reasons = new java.util.ArrayList<>();
        reasons.add("File reputation result: " + result.reputationStatus());
        reasons.add("Authenticode status: " + (result.signatureStatus() == null ? "NOT_REQUESTED" : result.signatureStatus()));
        reasons.add("SHA-256: " + result.sha256());
        if (result.description() != null && !result.description().isBlank()) reasons.add("Reputation evidence: " + result.description());
        return recordFinding(Instant.now(), "FILE", "FILE_INSPECTION", safeBasename(result.fileName()),
                null, score, reasons, result.sizeBytes());
    }

    private MonitorEventResult recordFinding(Instant timestamp, String type, String action, String resource,
                                            Long processId, int score, List<String> reasons) {
        return recordFinding(timestamp, type, action, resource, processId, score, reasons, null);
    }

    private MonitorEventResult recordFinding(Instant timestamp, String type, String action, String resource,
                                            Long processId, int score, List<String> reasons, Long sizeBytes) {
        RiskAssessment risk = riskEngine.assess(new AnalysisSignals(score, reasons));
        Decision decision = policyEngine.evaluateRiskLevel(risk.level());
        return repository.save(new MonitorEventResult(null, timestamp == null ? Instant.now() : timestamp,
                type, action, resource, processId, sizeBytes, risk.score(), risk.level().name(), decision.name(), risk.reasons()));
    }

    private String safeBasename(String resourceName) {
        if (resourceName == null || resourceName.isBlank()) return "script-file";
        String value = resourceName.replace('\\', '/');
        String basename = value.substring(value.lastIndexOf('/') + 1);
        return basename.length() > 160 ? basename.substring(0, 160) : basename;
    }

    private WindowsEventRule windowsRule(WindowsSecurityEvent event) {
        if (event == null || event.logName() == null) return null;
        String log = event.logName();
        if (log.contains("Windows Defender/Operational")) {
            return switch (event.eventId()) {
                case 1116 -> new WindowsEventRule("DEFENDER_THREAT_DETECTED", 90,
                        "Microsoft Defender reported a threat detection; this is a provider finding, not an AI WatchDog enforcement result.");
                case 1117 -> new WindowsEventRule("DEFENDER_ACTION_REPORTED", 90,
                        "Microsoft Defender reported an action for a threat; verify the Defender event outcome.");
                case 1118 -> new WindowsEventRule("DEFENDER_ACTION_FAILED", 90,
                        "Microsoft Defender reported that an action failed; review the Defender event and protection status.");
                case 5007 -> new WindowsEventRule("DEFENDER_CONFIGURATION_CHANGED", 60,
                        "Microsoft Defender reported a configuration change; this event alone does not establish malicious activity.");
                default -> null;
            };
        }
        if ("Security".equalsIgnoreCase(log)) {
            return switch (event.eventId()) {
                case 1102 -> new WindowsEventRule("SECURITY_AUDIT_LOG_CLEARED", 80,
                        "Windows Security reported that its audit log was cleared; verify the change and surrounding events.");
                case 4719 -> new WindowsEventRule("SECURITY_AUDIT_POLICY_CHANGED", 60,
                        "Windows Security reported an audit policy change; this event alone does not establish malicious activity.");
                case 4697 -> new WindowsEventRule("WINDOWS_SERVICE_INSTALLED", 60,
                        "Windows Security reported a service installation; verify the installer and service owner.");
                case 4698 -> new WindowsEventRule("WINDOWS_SCHEDULED_TASK_CREATED", 60,
                        "Windows Security reported a scheduled task creation; verify its purpose and owner.");
                default -> null;
            };
        }
        return null;
    }

    private record WindowsEventRule(String action, int score, String reason) { }

    private String canonical(String value) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException("Event fields are required");
        return value.trim().toUpperCase(Locale.ROOT);
    }
}
