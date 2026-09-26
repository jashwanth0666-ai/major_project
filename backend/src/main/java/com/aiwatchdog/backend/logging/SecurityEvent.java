package com.aiwatchdog.backend.logging;

import java.time.Instant;

public record SecurityEvent(
        Long id,
        Instant timestamp,
        String url,
        double phishingProbability,
        int riskScore,
        String riskLevel,
        String prediction,
        String decision
) {
}