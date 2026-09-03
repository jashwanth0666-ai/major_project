package com.aiwatchdog.model;

import java.util.List;

public record AnalysisResult(String url, ThreatLevel level, int score, int confidence, List<String> reasons, List<String> features, String decision) {
    public String label() { return level == ThreatLevel.HIGH_RISK ? "HIGH RISK" : level.name(); }
}
