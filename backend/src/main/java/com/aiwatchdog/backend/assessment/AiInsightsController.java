package com.aiwatchdog.backend.assessment;

import com.aiwatchdog.backend.logging.SecurityEventRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/** Aggregate-only LLM insights endpoint. Raw URLs and event details are never sent to the LLM. */
@RestController
@RequestMapping("/api/v1/threat-assessments")
public class AiInsightsController {
    private final SecurityEventRepository events;
    private final LlmExplanationService llm;

    public AiInsightsController(SecurityEventRepository events, LlmExplanationService llm) {
        this.events = events;
        this.llm = llm;
    }

    @GetMapping("/insights")
    public AiInsightsResponse insights(@RequestParam(defaultValue = "Last 7 days") String period) {
        long days = switch (period) {
            case "Last 24 hours" -> 1;
            case "Last 7 days" -> 7;
            case "Last 30 days" -> 30;
            default -> throw new IllegalArgumentException("Unsupported insights period.");
        };
        Instant end = Instant.now();
        Instant start = end.minus(Duration.ofDays(days));
        Instant previousStart = start.minus(Duration.ofDays(days));
        var current = events.getInsightPeriodMetrics(start, end);
        var previous = events.getInsightPeriodMetrics(previousStart, start);
        Map<String, Object> aggregate = new LinkedHashMap<>();
        aggregate.put("current", metricsForLlm(current));
        aggregate.put("previousEqualLengthPeriod", metricsForLlm(previous));
        aggregate.put("assessmentCountChange", current.urlAssessments() - previous.urlAssessments());
        aggregate.put("phishingPredictionChange", current.phishingPredictions() - previous.phishingPredictions());
        aggregate.put("linkedFalsePositiveReportChange", current.reportedFalsePositives() - previous.reportedFalsePositives());
        aggregate.put("linkedFalseNegativeReportChange", current.reportedFalseNegatives() - previous.reportedFalseNegatives());
        AssessmentExplanation explanation = llm.summarizeInsights(period.toLowerCase(Locale.ROOT), aggregate);
        return new AiInsightsResponse(explanation, Instant.now(), start, period, current, previous);
    }

    private Map<String, Object> metricsForLlm(com.aiwatchdog.backend.logging.InsightPeriodMetrics metrics) {
        Map<String, Object> safe = new LinkedHashMap<>();
        safe.put("urlAssessments", metrics.urlAssessments());
        safe.put("phishingPredictions", metrics.phishingPredictions());
        safe.put("highRisk", metrics.highRisk());
        safe.put("suspicious", metrics.suspicious());
        safe.put("blocked", metrics.blocked());
        safe.put("review", metrics.review());
        safe.put("meanPhishingScorePercent", metrics.meanPhishingScore() == null
                ? "unavailable" : metrics.meanPhishingScore() * 100.0);
        safe.put("feedbackLabels", metrics.feedbackLabels());
        safe.put("userReportedFalsePositives", metrics.reportedFalsePositives());
        safe.put("userReportedFalseNegatives", metrics.reportedFalseNegatives());
        safe.put("userMarkedCorrect", metrics.feedbackMarkedCorrect());
        safe.put("hostSignalCounts", metrics.signalCounts());
        return safe;
    }
}
