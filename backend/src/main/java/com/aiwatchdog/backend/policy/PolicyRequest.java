package com.aiwatchdog.backend.policy;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.DecimalMax;
import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Max;

public record PolicyRequest(
        @NotBlank String url,
        @JsonProperty("phishing_probability") @NotNull @DecimalMin("0.0") @DecimalMax("1.0") Double phishingProbability,
        @JsonProperty("risk_score") @NotNull @Min(0) @Max(100) Integer riskScore,
        @JsonProperty("risk_level") @NotBlank String riskLevel,
        @NotBlank String prediction) {
}