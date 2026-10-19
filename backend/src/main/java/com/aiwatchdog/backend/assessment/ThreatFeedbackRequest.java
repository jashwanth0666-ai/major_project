package com.aiwatchdog.backend.assessment;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record ThreatFeedbackRequest(
        @NotBlank @Pattern(regexp = "[0-9a-fA-F-]{36}") String assessmentId,
        @Pattern(regexp = "[0-9a-fA-F-]{36}") String correlationId,
        @NotBlank @Pattern(regexp = "FALSE_POSITIVE|FALSE_NEGATIVE|CORRECT") String label) { }
