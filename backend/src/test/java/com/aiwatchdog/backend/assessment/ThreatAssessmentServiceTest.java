package com.aiwatchdog.backend.assessment;

import com.aiwatchdog.backend.dto.MlPredictionResponse;
import com.aiwatchdog.backend.fileshield.dto.FileScanResponse;
import com.aiwatchdog.backend.fileshield.model.ReputationStatus;
import com.aiwatchdog.backend.fileshield.model.ScanStatus;
import com.aiwatchdog.backend.fileshield.service.FileShieldService;
import com.aiwatchdog.backend.logging.SecurityEventLogger;
import com.aiwatchdog.backend.policy.Decision;
import com.aiwatchdog.backend.policy.PolicyEngine;
import com.aiwatchdog.backend.service.MlServiceClient;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import java.nio.file.Path;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import org.mockito.ArgumentCaptor;

class ThreatAssessmentServiceTest {
    private MlServiceClient ml;
    private PolicyEngine policy;
    private FileShieldService files;
    private SecurityEventLogger logger;
    private ThreatAssessmentService service;
    private AssessmentExplanationService explanationService;

    @BeforeEach void setup() {
        ml = mock(MlServiceClient.class); policy = mock(PolicyEngine.class);
        files = mock(FileShieldService.class); logger = mock(SecurityEventLogger.class);
        explanationService = mock(AssessmentExplanationService.class);
        service = new ThreatAssessmentService(ml, policy, files, logger);
    }

    @Test void urlAssessmentPreservesModelOutputAndExistingPolicyVerdict() {
        when(ml.predict("https://example.test")).thenReturn(new MlPredictionResponse(
                "https://example.test", .99, 91, "HIGH_RISK", "PHISHING", .15, List.of("model reason")));
        when(policy.evaluate(any())).thenReturn(Decision.BLOCK);
        var result = service.assessUrl("https://example.test");
        assertEquals("BLOCK", result.policyVerdict());
        assertEquals("PHISHING", ((MlPredictionResponse) result.sources().get("urlModel")).prediction());
        assertEquals("COMPLETE", result.status());
        verify(logger).logAssessment(any());
    }

    @Test
    void groqConsoleAssessmentKeepsModelAuthoritiesWhenExplanationIsUntrusted() {
        String url = "https://console.groq.com/dashboard/metrics";
        List<String> modelReasons = List.of("No major URL-level warning indicators detected");
        MlPredictionResponse modelResponse = new MlPredictionResponse(
                url, 0.993671, 99, "HIGH_RISK", "PHISHING", .15, modelReasons);
        when(ml.predict("https://console.groq.com")).thenReturn(new MlPredictionResponse(
                "https://console.groq.com", 0.993671, 99, "HIGH_RISK", "PHISHING", .15, modelReasons));
        when(policy.evaluate(any())).thenReturn(Decision.BLOCK);
        when(explanationService.explain(any())).thenReturn(new AssessmentExplanation(
                "The supplied evidence was reviewed.", List.of("LLM-generated text"),
                List.of(), "Review through a trusted channel.", "llm", false));

        service = new ThreatAssessmentService(ml, policy, files, logger,
                host -> UrlReputationResult.disabled(host),
                new ConfiguredLocalDomainRuleService("", ""), explanationService);

        ThreatAssessment result = service.assessUrl(url);

        MlPredictionResponse returnedModel = (MlPredictionResponse) result.sources().get("urlModel");
        assertEquals("PHISHING", returnedModel.prediction());
        assertEquals(0.993671, returnedModel.phishing_probability(), 0.0000005);
        assertEquals(99, returnedModel.risk_score());
        assertEquals("HIGH_RISK", returnedModel.risk_level());
        assertEquals(modelReasons, returnedModel.reasons());
        assertEquals("BLOCK", result.policyVerdict());
        assertEquals("llm", result.explanationDetails().generatedBy());
        verify(policy).evaluate(argThat(request ->
                request.riskScore() == 99
                        && "HIGH_RISK".equals(request.riskLevel())
                        && "PHISHING".equals(request.prediction())));
    }

    @Test void urlAuditRedactsQuerySecretsWhileResponseKeepsSourcePrediction() {
        String url = "https://example.test/private?token=secret-value";
        when(ml.predict("https://example.test")).thenReturn(new MlPredictionResponse(
                "https://example.test", .01, 1, "SAFE", "BENIGN", .15, List.of()));
        when(policy.evaluate(any())).thenReturn(Decision.ALLOW);
        var response = service.assessUrl(url);
        assertEquals("https://example.test", ((MlPredictionResponse) response.sources().get("urlModel")).url());
        assertEquals(url, response.sources().get("submittedUrl"));
        ArgumentCaptor<com.aiwatchdog.backend.logging.SecurityEvent> captor =
                ArgumentCaptor.forClass(com.aiwatchdog.backend.logging.SecurityEvent.class);
        verify(logger).logAssessment(captor.capture());
        assertFalse(captor.getValue().detailsJson().contains("secret-value"));
        assertFalse(captor.getValue().subjectId().contains("token"));
    }

    @Test void knownMaliciousHashBlocksEvenWhenPeUnavailable() {
        when(files.scanFile(any(Path.class))).thenReturn(scan(ReputationStatus.KNOWN_MALICIOUS));
        when(ml.analyzeFile("C:/approved/sample.exe")).thenThrow(new RuntimeException("down"));
        var result = service.assessFile("C:/approved/sample.exe");
        assertEquals("BLOCK", result.policyVerdict());
        assertEquals("PARTIAL", result.status());
        assertTrue(result.errors().stream().anyMatch(e -> e.contains("PE analysis")));
    }

    @Test void unknownHashNeverBecomesCleanAndPeHeuristicOnlyRequestsReview() throws Exception {
        when(files.scanFile(any(Path.class))).thenReturn(scan(ReputationStatus.UNKNOWN));
        when(ml.analyzeFile("C:/approved/sample.exe")).thenReturn(new ObjectMapper().readTree(
                "{\"status\":\"ANALYZED\",\"risk_score\":95,\"sensitive_imports\":[\"WriteProcessMemory\"]}"));
        var result = service.assessFile("C:/approved/sample.exe");
        assertEquals("REVIEW", result.policyVerdict());
        assertTrue(result.explanation().stream().anyMatch(e -> e.contains("not clean")));
        assertFalse("MALICIOUS".equals(result.policyVerdict()));
        assertInstanceOf(java.util.Map.class, result.sources().get("staticPe"));
        assertEquals("ANALYZED", ((java.util.Map<?, ?>) result.sources().get("staticPe")).get("status"));
    }

    @Test void knownCleanAndLowPeIndicatorsAllowWithoutCombiningScores() throws Exception {
        when(files.scanFile(any(Path.class))).thenReturn(scan(ReputationStatus.KNOWN_CLEAN));
        when(ml.analyzeFile("C:/approved/sample.exe")).thenReturn(new ObjectMapper().readTree(
                "{\"status\":\"ANALYZED\",\"risk_score\":10}"));
        var result = service.assessFile("C:/approved/sample.exe");
        assertEquals("ALLOW", result.policyVerdict());
        assertEquals("COMPLETE", result.status());
    }

    @Test void reputationLookupErrorAndUrlPredictionFailureRemainExplicit() {
        when(files.scanFile(any(Path.class))).thenReturn(scan(ReputationStatus.LOOKUP_ERROR));
        when(ml.analyzeFile(anyString())).thenThrow(new RuntimeException("offline"));
        var fileResult = service.assessFile("C:/approved/sample.exe");
        assertEquals("REVIEW", fileResult.policyVerdict());
        assertEquals("PARTIAL", fileResult.status());
        assertTrue(fileResult.errors().stream().anyMatch(e -> e.contains("Reputation lookup failed")));

        when(ml.predict("https://unavailable.test")).thenThrow(new RuntimeException("offline"));
        var urlResult = service.assessUrl("https://unavailable.test");
        assertEquals("REVIEW", urlResult.policyVerdict());
        assertEquals("PARTIAL", urlResult.status());
        assertEquals("UNAVAILABLE", ((java.util.Map<?, ?>) urlResult.sources().get("urlModel")).get("status"));
    }

    @Test void auditFailureIsReturnedAsPartialInsteadOfClaimingPersistence() {
        when(files.scanFile(any(Path.class))).thenReturn(scan(ReputationStatus.UNKNOWN));
        when(ml.analyzeFile(anyString())).thenThrow(new RuntimeException("offline"));
        doThrow(new IllegalStateException("db down")).when(logger).logAssessment(any());
        var result = service.assessFile("C:/approved/sample.exe");
        assertEquals("PARTIAL", result.status());
        assertTrue(result.errors().stream().anyMatch(e -> e.contains("audit event could not be persisted")));
    }

    private FileScanResponse scan(ReputationStatus status) {
        return new FileScanResponse("sample.exe", "a".repeat(64), status, ScanStatus.COMPLETED,
                "test", 42, "test-db", null);
    }
}
