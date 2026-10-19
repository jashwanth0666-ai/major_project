package com.aiwatchdog.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.List;
import java.util.Map;

@JsonIgnoreProperties(ignoreUnknown = true)
public record InsightPeriodMetrics(long urlAssessments, long phishingPredictions, long highRisk,
        long suspicious, long blocked, long review, Double meanPhishingScore,
        long feedbackLabels, long reportedFalsePositives, long reportedFalseNegatives,
        long feedbackMarkedCorrect, Map<String, Long> signalCounts, List<String> feedbackAssessmentIds) { }
