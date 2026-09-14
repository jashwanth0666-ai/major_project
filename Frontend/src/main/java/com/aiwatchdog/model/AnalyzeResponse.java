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
                List<String> reasons) {
}
