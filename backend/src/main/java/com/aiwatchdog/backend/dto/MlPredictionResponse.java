package com.aiwatchdog.backend.dto;

import java.util.List;

public record MlPredictionResponse(
        String url,
        double phishing_probability,
        int risk_score,
        String risk_level,
        String prediction,
        double threshold,
        List<String> reasons) {
}
