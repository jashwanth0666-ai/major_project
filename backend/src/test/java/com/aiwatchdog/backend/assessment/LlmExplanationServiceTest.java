package com.aiwatchdog.backend.assessment;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class LlmExplanationServiceTest {
    @Test
    void disabledLayerReturnsDeterministicFallbackWithoutCredentials() {
        var service = new LlmExplanationService(false, "", "gpt-4o-mini",
                "https://api.openai.com/v1/chat/completions", 3000);
        var assessment = new ThreatAssessment(null, null, "URL", "example.test",
                null, Map.of(), "BLOCK", "COMPLETE", List.of("model flagged risk"),
                List.of(), "test-correlation");

        var explanation = service.explain(assessment);

        assertEquals("rules", explanation.generatedBy());
        assertTrue(explanation.fallbackUsed());
        assertEquals("BLOCK", assessment.policyVerdict());
        assertEquals(List.of("model flagged risk"), assessment.explanation());
    }

    @Test
    void fallbackDoesNotTreatUnavailableEvidenceAsClean() {
        var assessment = new ThreatAssessment(null, null, "URL", "example.test",
                null, Map.of(), "REVIEW", "PARTIAL", List.of(),
                List.of("URL reputation provider is unavailable."), "test-correlation");

        var explanation = AssessmentExplanation.fallback(assessment);

        assertTrue(explanation.uncertainties().contains("URL reputation provider is unavailable."));
        assertFalse(explanation.summary().toLowerCase().contains("safe"));
    }
}
