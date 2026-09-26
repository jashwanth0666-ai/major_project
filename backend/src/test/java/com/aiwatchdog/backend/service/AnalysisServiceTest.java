package com.aiwatchdog.backend.service;

import com.aiwatchdog.backend.dto.AnalyzeResponse;
import com.aiwatchdog.backend.dto.MlPredictionResponse;
import com.aiwatchdog.backend.logging.SecurityEventLogger;
import com.aiwatchdog.backend.policy.Decision;
import com.aiwatchdog.backend.policy.PolicyEngine;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class AnalysisServiceTest {

    @Test
    void validUrlUsesPolicyDecisionAndPreservesMlAssessment() {

        MlServiceClient mlServiceClient = mock(MlServiceClient.class);
        PolicyEngine policyEngine = mock(PolicyEngine.class);
        SecurityEventLogger securityEventLogger =
                mock(SecurityEventLogger.class);

        AnalysisService service = new AnalysisService(
                mlServiceClient,
                policyEngine,
                securityEventLogger);

        MlPredictionResponse prediction =
                new MlPredictionResponse(
                        "https://example.com",
                        0.37,
                        37,
                        "LOW_RISK",
                        "BENIGN",
                        0.15,
                        List.of("example reason"));

        when(mlServiceClient.predict("https://example.com"))
                .thenReturn(prediction);

        when(policyEngine.evaluate(any()))
                .thenReturn(Decision.REVIEW);

        AnalyzeResponse response =
                service.analyze("https://example.com");

        assertEquals("https://example.com", response.url());
        assertEquals(0.37, response.phishing_probability());
        assertEquals(37, response.risk_score());
        assertEquals("LOW_RISK", response.risk_level());
        assertEquals("BENIGN", response.prediction());
        assertEquals("REVIEW", response.decision());
        assertEquals(0.15, response.threshold());
        assertEquals(
                List.of("example reason"),
                response.reasons());

        verify(mlServiceClient)
                .predict("https://example.com");

        verify(policyEngine)
                .evaluate(any());

        verify(securityEventLogger)
                .log(any());
    }

    @Test
    void malformedUrlIsRejectedBeforeMlCall() {

        MlServiceClient mlServiceClient = mock(MlServiceClient.class);
        PolicyEngine policyEngine = mock(PolicyEngine.class);
        SecurityEventLogger securityEventLogger =
                mock(SecurityEventLogger.class);

        AnalysisService service = new AnalysisService(
                mlServiceClient,
                policyEngine,
                securityEventLogger);

        assertThrows(
                InvalidRequestException.class,
                () -> service.analyze("not-a-url"));

        verifyNoInteractions(mlServiceClient);
    }

    @Test
    void blankUrlIsRejectedBeforeMlCall() {

        MlServiceClient mlServiceClient = mock(MlServiceClient.class);
        PolicyEngine policyEngine = mock(PolicyEngine.class);
        SecurityEventLogger securityEventLogger =
                mock(SecurityEventLogger.class);

        AnalysisService service = new AnalysisService(
                mlServiceClient,
                policyEngine,
                securityEventLogger);

        assertThrows(
                InvalidRequestException.class,
                () -> service.analyze(" "));

        verifyNoInteractions(mlServiceClient);
    }

    @Test
    void unavailableMlServiceIsPropagated() {

        MlServiceClient mlServiceClient = mock(MlServiceClient.class);
        PolicyEngine policyEngine = mock(PolicyEngine.class);
        SecurityEventLogger securityEventLogger =
                mock(SecurityEventLogger.class);

        when(mlServiceClient.predict("https://example.com"))
                .thenThrow(new MlServiceException(
                        "AI analysis service is unavailable.",
                        MlServiceException.FailureType.UNAVAILABLE,
                        null));

        AnalysisService service = new AnalysisService(
                mlServiceClient,
                policyEngine,
                securityEventLogger);

        MlServiceException exception = assertThrows(
                MlServiceException.class,
                () -> service.analyze("https://example.com"));

        assertEquals(
                MlServiceException.FailureType.UNAVAILABLE,
                exception.failureType());
    }

    @Test
    void timedOutMlServiceIsPropagated() {

        MlServiceClient mlServiceClient = mock(MlServiceClient.class);
        PolicyEngine policyEngine = mock(PolicyEngine.class);
        SecurityEventLogger securityEventLogger =
                mock(SecurityEventLogger.class);

        when(mlServiceClient.predict("https://example.com"))
                .thenThrow(new MlServiceException(
                        "ML service response timed out.",
                        MlServiceException.FailureType.TIMEOUT,
                        null));

        AnalysisService service = new AnalysisService(
                mlServiceClient,
                policyEngine,
                securityEventLogger);

        MlServiceException exception = assertThrows(
                MlServiceException.class,
                () -> service.analyze("https://example.com"));

        assertEquals(
                MlServiceException.FailureType.TIMEOUT,
                exception.failureType());
    }

    @Test
    void malformedMlResponseIsPropagated() {

        MlServiceClient mlServiceClient = mock(MlServiceClient.class);
        PolicyEngine policyEngine = mock(PolicyEngine.class);
        SecurityEventLogger securityEventLogger =
                mock(SecurityEventLogger.class);

        when(mlServiceClient.predict("https://example.com"))
                .thenThrow(new MlServiceException(
                        "ML service returned an unusable response.",
                        MlServiceException.FailureType.MALFORMED_RESPONSE,
                        null));

        AnalysisService service = new AnalysisService(
                mlServiceClient,
                policyEngine,
                securityEventLogger);

        MlServiceException exception = assertThrows(
                MlServiceException.class,
                () -> service.analyze("https://example.com"));

        assertEquals(
                MlServiceException.FailureType.MALFORMED_RESPONSE,
                exception.failureType());
    }
}