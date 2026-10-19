package com.aiwatchdog.model;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.List;
import java.util.Map;

/** Unified assessment returned by Spring; source nodes keep each producer's original contract. */
public record ThreatAssessmentResult(String assessmentId, String timestamp, String subjectType,
        String subjectId, String sha256, Map<String, JsonNode> sources, String policyVerdict,
        String status, List<String> explanation, List<String> errors, String correlationId,
        ThreatAssessmentExplanation explanationDetails) { }
