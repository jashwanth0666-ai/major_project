package com.aiwatchdog.service;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/** Run with FastAPI and Spring active: mvn -Dtest=ApiServiceLiveIT test. */
class ApiServiceLiveIT {
    @Test
    void usesLiveSpringAnalysisHealthStatsAndHistoryEndpoints() throws Exception {
        ApiService api = new ApiService();
        var health = api.getServiceHealth();
        assertTrue(health.isFullyAvailable(), "Spring and FastAPI must both be healthy");

        var result = api.analyzeUrl("https://example.com");
        assertEquals("SAFE", result.riskLevel());
        assertEquals("BENIGN", result.prediction());
        assertEquals("ALLOW", result.decision());
        assertTrue(api.getSecurityEventStats().totalEvents() >= 1);
        assertTrue(api.getRecentEvents().stream().anyMatch(event -> "https://example.com".equals(event.url())));
        assertNotNull(api.getRecentMonitorEvents());
    }
}
