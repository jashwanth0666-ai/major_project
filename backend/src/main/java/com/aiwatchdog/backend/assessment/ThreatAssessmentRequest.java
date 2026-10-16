package com.aiwatchdog.backend.assessment;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record ThreatAssessmentRequest(@NotBlank @Size(max = 4096) String path) { }
