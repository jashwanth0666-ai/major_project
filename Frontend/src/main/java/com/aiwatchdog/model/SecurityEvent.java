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
        String decision) {
}
