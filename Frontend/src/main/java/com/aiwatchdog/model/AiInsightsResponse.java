package com.aiwatchdog.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public record AiInsightsResponse(ThreatAssessmentExplanation insight, String generatedAt,
        String periodStart, String period, InsightPeriodMetrics current, InsightPeriodMetrics previous) { }
