package com.aiwatchdog.backend.assessment;

import com.aiwatchdog.backend.logging.InsightPeriodMetrics;

import java.time.Instant;

/** LLM interpretation plus reproducible period metadata and feedback-linked review references. */
public record AiInsightsResponse(AssessmentExplanation insight, Instant generatedAt, Instant periodStart,
        String period, InsightPeriodMetrics current, InsightPeriodMetrics previous) { }
