package com.aiwatchdog.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public record SecurityEvent(
        Long id,
        String timestamp,
        String url,
        double phishingProbability,
        int riskScore,
        String riskLevel,
        String prediction,
        String decision,
        String eventType,
        String subjectType,
        String subjectId,
        String correlationId,
        String detailsJson) {

    public SecurityEvent(Long id, String timestamp, String url, double phishingProbability,
            int riskScore, String riskLevel, String prediction, String decision) {
        this(id, timestamp, url, phishingProbability, riskScore, riskLevel, prediction, decision,
                "URL_ANALYSIS", "URL", url, null, null);
    }
}
