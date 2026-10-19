package com.aiwatchdog.backend.dto;

import java.util.List;

public record AnalyzeResponse(
        String url,
        double phishing_probability,
        int risk_score,
        String risk_level,
        String prediction,
        String decision,
        double threshold,
        List<String> reasons,
        String assessmentId,
        String correlationId) {

    public AnalyzeResponse(String url, double phishingProbability, int riskScore,
                           String riskLevel, String prediction, String decision,
                           double threshold, List<String> reasons) {
        this(url, phishingProbability, riskScore, riskLevel, prediction, decision,
                threshold, reasons, null, null);
    }
}
