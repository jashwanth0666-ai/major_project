package com.aiwatchdog.backend.logging;

import java.time.Instant;

public record SecurityEvent(
        Long id,
        Instant timestamp,
        String url,
        Double phishingProbability,
        Integer riskScore,
        String riskLevel,
        String prediction,
        String decision,
        String eventType,
        String subjectType,
        String subjectId,
        String correlationId,
        String detailsJson
) {
    public SecurityEvent(Long id, Instant timestamp, String url, double phishingProbability,
                         int riskScore, String riskLevel, String prediction, String decision) {
        this(id, timestamp, url, phishingProbability, riskScore, riskLevel, prediction, decision,
                "URL_ANALYSIS", "URL", url, null, null);
    }
}
