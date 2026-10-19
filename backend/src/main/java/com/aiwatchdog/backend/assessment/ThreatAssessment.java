package com.aiwatchdog.backend.assessment;

import java.util.List;
import java.util.Map;
import java.util.UUID;

/** Unified evidence record; source-specific scores retain their original meanings. */
public record ThreatAssessment(String assessmentId, String timestamp, String subjectType,
                              String subjectId, String sha256, Map<String, Object> sources,
                              String policyVerdict, String status, List<String> explanation,
                              List<String> errors, String correlationId,
                              AssessmentExplanation explanationDetails) {
    public ThreatAssessment(String assessmentId, String timestamp, String subjectType,
                            String subjectId, String sha256, Map<String, Object> sources,
                            String policyVerdict, String status, List<String> explanation,
                            List<String> errors, String correlationId) {
        this(assessmentId, timestamp, subjectType, subjectId, sha256, sources, policyVerdict,
                status, explanation, errors, correlationId, null);
    }

    public ThreatAssessment {
        if (assessmentId == null) assessmentId = UUID.randomUUID().toString();
        if (timestamp == null) timestamp = java.time.Instant.now().toString();
        sources = sources == null ? Map.of() : Map.copyOf(sources);
        explanation = explanation == null ? List.of() : List.copyOf(explanation);
        errors = errors == null ? List.of() : List.copyOf(errors);
        if (explanationDetails == null) {
            explanationDetails = AssessmentExplanation.fallback(policyVerdict, explanation, errors);
        }
    }
}
