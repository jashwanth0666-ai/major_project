package com.aiwatchdog.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public record ThreatAssessmentExplanation(
        String summary,
        List<String> supportingEvidence,
        List<String> uncertainties,
        String recommendedAction,
        String generatedBy,
        boolean fallbackUsed) {
}
