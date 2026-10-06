package com.aiwatchdog.backend.monitor;

import com.aiwatchdog.backend.policy.Decision;
import com.aiwatchdog.backend.policy.PolicyEngine;
import org.springframework.stereotype.Service;
import java.time.Instant;
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

    private String canonical(String value) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException("Event fields are required");
        return value.trim().toUpperCase(Locale.ROOT);
    }
}
