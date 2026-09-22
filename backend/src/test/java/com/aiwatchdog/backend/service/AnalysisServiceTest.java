package com.aiwatchdog.backend.service;

import com.aiwatchdog.backend.dto.AnalyzeResponse;
import com.aiwatchdog.backend.dto.MlPredictionResponse;
import com.aiwatchdog.backend.policy.Decision;
import com.aiwatchdog.backend.policy.PolicyEngine;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AnalysisServiceTest {

        @Mock
        private MlServiceClient mlServiceClient;

        @Mock
        private PolicyEngine policyEngine;

        @Test
        void validUrlUsesPolicyDecisionAndPreservesMlAssessment() {
                MlPredictionResponse prediction = new MlPredictionResponse(
                                "https://example.com",
                                0.37,
                                37,
                                "LOW_RISK",
                                "BENIGN",
                                "BLOCK",
                                0.15,
                                List.of("example reason"));
                when(mlServiceClient.predict("https://example.com")).thenReturn(prediction);
                when(policyEngine.evaluate(org.mockito.ArgumentMatchers.any())).thenReturn(Decision.REVIEW);

                AnalyzeResponse response = new AnalysisService(mlServiceClient, policyEngine)
                                .analyze("https://example.com");

                assertEquals(prediction.phishing_probability(), response.phishing_probability());
                assertEquals(prediction.risk_score(), response.risk_score());
                assertEquals(prediction.risk_level(), response.risk_level());
                assertEquals("REVIEW", response.decision());
                assertEquals(prediction.threshold(), response.threshold());
                verify(mlServiceClient).predict("https://example.com");
                verify(policyEngine).evaluate(org.mockito.ArgumentMatchers.any());
        }

        @Test
        void malformedUrlIsRejectedBeforeMlCall() {
                AnalysisService service = new AnalysisService(mlServiceClient, policyEngine);

                assertThrows(InvalidRequestException.class, () -> service.analyze("not-a-url"));
                verifyNoInteractions(mlServiceClient);
        }

        @Test
        void blankUrlIsRejectedBeforeMlCall() {
                AnalysisService service = new AnalysisService(mlServiceClient, policyEngine);

                assertThrows(InvalidRequestException.class, () -> service.analyze(" "));
                verifyNoInteractions(mlServiceClient);
        }

        @Test
        void unavailableMlServiceIsPropagated() {
                when(mlServiceClient.predict("https://example.com"))
                                .thenThrow(new MlServiceException(
                                                "AI analysis service is unavailable.",
                                                MlServiceException.FailureType.UNAVAILABLE,
                                                null));

                MlServiceException exception = assertThrows(
                                MlServiceException.class,
                                () -> new AnalysisService(mlServiceClient, policyEngine)
                                                .analyze("https://example.com"));

                assertEquals(MlServiceException.FailureType.UNAVAILABLE, exception.failureType());
        }

        @Test
        void timedOutMlServiceIsPropagated() {
                when(mlServiceClient.predict("https://example.com"))
                                .thenThrow(new MlServiceException(
                                                "ML service response timed out.",
                                                MlServiceException.FailureType.TIMEOUT,
                                                null));

                MlServiceException exception = assertThrows(
                                MlServiceException.class,
                                () -> new AnalysisService(mlServiceClient, policyEngine)
                                                .analyze("https://example.com"));

                assertEquals(MlServiceException.FailureType.TIMEOUT, exception.failureType());
        }

        @Test
        void malformedMlResponseIsPropagated() {
                when(mlServiceClient.predict("https://example.com"))
                                .thenThrow(new MlServiceException(
                                                "ML service returned an unusable response.",
                                                MlServiceException.FailureType.MALFORMED_RESPONSE,
                                                null));

                MlServiceException exception = assertThrows(
                                MlServiceException.class,
                                () -> new AnalysisService(mlServiceClient, policyEngine)
                                                .analyze("https://example.com"));

                assertEquals(MlServiceException.FailureType.MALFORMED_RESPONSE, exception.failureType());
        }
}

