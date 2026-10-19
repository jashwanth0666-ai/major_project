package com.aiwatchdog.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public record AnalyzeResponse(
                String url,
                @JsonProperty("phishing_probability") double phishingProbability,
                @JsonProperty("risk_score") int riskScore,
                @JsonProperty("risk_level") String riskLevel,
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
