package com.aiwatchdog.backend.controller;

import com.aiwatchdog.backend.dto.AnalyzeResponse;
import com.aiwatchdog.backend.service.AnalysisService;
import com.aiwatchdog.backend.service.MlServiceException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.validation.beanvalidation.LocalValidatorFactoryBean;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(MockitoExtension.class)
class AnalyzeControllerTest {

    private MockMvc mockMvc;

    @Mock
    private AnalysisService analysisService;

    @BeforeEach
    void setUp() {
        LocalValidatorFactoryBean validator = new LocalValidatorFactoryBean();
        validator.afterPropertiesSet();

        mockMvc = MockMvcBuilders
                .standaloneSetup(new AnalyzeController(analysisService))
                .setControllerAdvice(new GlobalExceptionHandler())
                .setValidator(validator)
                .build();
    }

    @Test
    void validRequestReturnsAnalysis() throws Exception {
        when(analysisService.analyze("https://example.com"))
                .thenReturn(new AnalyzeResponse(
                        "https://example.com",
                        0.01,
                        1,
                        "SAFE",
                        "BENIGN",
                        "ALLOW",
                        0.15,
                        java.util.List.of()));

        mockMvc.perform(post("/api/v1/analyze")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"url\":\"https://example.com\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.risk_level").value("SAFE"));
    }

    @Test
    void blankUrlReturnsBadRequest() throws Exception {
        mockMvc.perform(post("/api/v1/analyze")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"url\":\"   \"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("INVALID_REQUEST"));
    }

    @Test
    void missingUrlReturnsBadRequest() throws Exception {
        mockMvc.perform(post("/api/v1/analyze")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void unavailableMlServiceReturns503() throws Exception {
        when(analysisService.analyze("https://example.com"))
                .thenThrow(new MlServiceException(
                        "AI analysis service is unavailable.",
                        MlServiceException.FailureType.UNAVAILABLE,
                        null));

        performRequestAndExpectStatus(503, "ML_SERVICE_UNAVAILABLE");
    }

    @Test
    void timedOutMlServiceReturns504() throws Exception {
        when(analysisService.analyze("https://example.com"))
                .thenThrow(new MlServiceException(
                        "ML service response timed out.",
                        MlServiceException.FailureType.TIMEOUT,
                        null));

        performRequestAndExpectStatus(504, "ML_SERVICE_TIMEOUT");
    }

    @Test
    void malformedMlResponseReturns502() throws Exception {
        when(analysisService.analyze("https://example.com"))
                .thenThrow(new MlServiceException(
                        "ML service returned an unusable response.",
                        MlServiceException.FailureType.MALFORMED_RESPONSE,
                        null));

        performRequestAndExpectStatus(502, "ML_SERVICE_BAD_RESPONSE");
    }

    @Test
    void unexpectedFailureReturns500() throws Exception {
        when(analysisService.analyze("https://example.com"))
                .thenThrow(new IllegalStateException("internal detail"));

        performRequestAndExpectStatus(500, "INTERNAL_ERROR");
    }

    private void performRequestAndExpectStatus(int status, String error) throws Exception {
        mockMvc.perform(post("/api/v1/analyze")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"url\":\"https://example.com\"}"))
                .andExpect(status().is(status))
                .andExpect(jsonPath("$.error").value(error))
                .andExpect(jsonPath("$.message").exists());
    }
}
