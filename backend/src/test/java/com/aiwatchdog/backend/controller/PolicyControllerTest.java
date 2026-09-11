package com.aiwatchdog.backend.controller;

import com.aiwatchdog.backend.policy.Decision;
import com.aiwatchdog.backend.policy.PolicyEngine;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.validation.beanvalidation.LocalValidatorFactoryBean;

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(MockitoExtension.class)
class PolicyControllerTest {

    private MockMvc mockMvc;

    @Mock
    private PolicyEngine policyEngine;

    @BeforeEach
    void setUp() {
        LocalValidatorFactoryBean validator = new LocalValidatorFactoryBean();
        validator.afterPropertiesSet();
        mockMvc = MockMvcBuilders.standaloneSetup(new PolicyController(policyEngine))
                .setControllerAdvice(new GlobalExceptionHandler())
                .setValidator(validator)
                .build();
    }

    @Test
    void evaluatesPolicy() throws Exception {
        when(policyEngine.evaluate(org.mockito.ArgumentMatchers.any())).thenReturn(Decision.BLOCK);

        mockMvc.perform(post("/api/policy/evaluate")
                .contentType(MediaType.APPLICATION_JSON)
                .content(
                        "{\"url\":\"https://example.com/login\",\"phishing_probability\":0.998925,\"risk_score\":100,\"risk_level\":\"HIGH_RISK\",\"prediction\":\"PHISHING\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.decision").value("BLOCK"));
    }

    @Test
    void rejectsInvalidRequest() throws Exception {
        mockMvc.perform(post("/api/policy/evaluate")
                .contentType(MediaType.APPLICATION_JSON)
                .content(
                        "{\"url\":\"https://example.com\",\"phishing_probability\":-0.1,\"risk_score\":10,\"risk_level\":\"SAFE\",\"prediction\":\"BENIGN\"}"))
                .andExpect(status().isBadRequest());
    }
}