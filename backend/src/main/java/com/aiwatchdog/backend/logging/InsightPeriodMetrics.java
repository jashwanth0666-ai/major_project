package com.aiwatchdog.backend.logging;

import java.util.List;
import java.util.Map;

/** Full-period aggregate used to ground AI Insights; contains no URLs or hostnames. */
public record InsightPeriodMetrics(long urlAssessments, long phishingPredictions, long highRisk,
        long suspicious, long blocked, long review, Double meanPhishingScore,
        long feedbackLabels, long reportedFalsePositives, long reportedFalseNegatives,
        long feedbackMarkedCorrect, Map<String, Long> signalCounts, List<String> feedbackAssessmentIds) {
    public InsightPeriodMetrics {
        signalCounts = signalCounts == null ? Map.of() : Map.copyOf(signalCounts);
        feedbackAssessmentIds = feedbackAssessmentIds == null ? List.of() : List.copyOf(feedbackAssessmentIds);
    }
}
