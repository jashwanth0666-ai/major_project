package com.aiwatchdog.backend.policy;

import com.fasterxml.jackson.annotation.JsonProperty;

public record PolicyResponse(
        String url,
        @JsonProperty("phishing_probability") Double phishingProbability,
        @JsonProperty("risk_score") Integer riskScore,
        @JsonProperty("risk_level") String riskLevel,
        String prediction,
        Decision decision) {
}