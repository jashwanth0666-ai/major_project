package com.aiwatchdog.backend.assessment;

import java.util.List;

/** Structured, non-authoritative explanation of an existing assessment. */
public record AssessmentExplanation(String summary, List<String> supportingEvidence,
                                    List<String> uncertainties, String recommendedAction,
                                    String generatedBy, boolean fallbackUsed) {
    public AssessmentExplanation {
        summary = summary == null ? "" : summary;
        supportingEvidence = supportingEvidence == null ? List.of() : List.copyOf(supportingEvidence);
        uncertainties = uncertainties == null ? List.of() : List.copyOf(uncertainties);
        recommendedAction = recommendedAction == null ? "" : recommendedAction;
        generatedBy = generatedBy == null ? "rules" : generatedBy;
    }

    public static AssessmentExplanation fallback(ThreatAssessment assessment) {
        return fallback(assessment.policyVerdict(), assessment.explanation(), assessment.errors());
    }

    public static AssessmentExplanation fallback(String policyVerdict, List<String> explanations,
                                                 List<String> errors) {
        List<String> evidence = explanations == null ? List.of() : explanations.stream().limit(5).toList();
        List<String> uncertainties = errors == null ? List.of() : errors.stream().limit(5).toList();
        String action = switch (policyVerdict == null ? "REVIEW" : policyVerdict) {
            case "BLOCK" -> "Do not open or submit data to this subject.";
            case "WARN" -> "Proceed only after reviewing the available evidence.";
            case "REVIEW" -> "Treat the assessment as inconclusive and verify through a trusted channel.";
            default -> "Continue using normal security precautions; an allow decision is not proof of safety.";
        };
        String summary = "The existing AI WatchDog model, evidence sources, and policy engine produced "
                + (policyVerdict == null ? "REVIEW" : policyVerdict) + ".";
        return new AssessmentExplanation(summary, evidence, uncertainties, action, "rules", true);
    }
}
