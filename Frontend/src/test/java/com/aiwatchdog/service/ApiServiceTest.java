package com.aiwatchdog.service;

import com.aiwatchdog.model.FileShieldSettingsUpdate;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

class ApiServiceTest {
    private HttpServer server;
    private ApiService api;
    private final AtomicReference<String> postedBody = new AtomicReference<>();
    private final AtomicReference<String> settingsMethod = new AtomicReference<>();
    private final AtomicReference<String> assessmentStatsBody = new AtomicReference<>(
            "{\"totalAssessments\":2,\"urlAssessments\":1,\"fileAssessments\":1,"
                    + "\"allowCount\":1,\"reviewCount\":1,\"warnCount\":0,\"blockCount\":0,"
                    + "\"completeCount\":1,\"partialCount\":1,\"knownMaliciousCount\":0,"
                    + "\"knownCleanCount\":0,\"unknownReputationCount\":1,\"lookupErrorCount\":0}");

    @BeforeEach
    void startServer() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/api/v1/health", exchange -> respond(exchange, 503,
                "{\"status\":\"DEGRADED\",\"spring_boot\":\"UP\",\"ml_service\":\"DOWN\"}"));
        server.createContext("/api/v1/analyze", exchange -> {
            postedBody.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            respond(exchange, 200, "{\"url\":\"https://example.com\",\"phishing_probability\":0.01,"
                    + "\"risk_score\":1,\"risk_level\":\"SAFE\",\"prediction\":\"BENIGN\","
                    + "\"decision\":\"ALLOW\",\"threshold\":0.15,\"reasons\":[\"clear\"]}");
        });
        server.createContext("/api/v1/threat-assessments/file", exchange -> {
            postedBody.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            respond(exchange, 200, "{\"assessmentId\":\"id-1\",\"timestamp\":\"2026-10-01T00:00:00Z\","
                    + "\"subjectType\":\"FILE\",\"subjectId\":\"abc\",\"sha256\":\"abc\","
                    + "\"sources\":{\"fileReputation\":{\"reputationStatus\":\"UNKNOWN\"}},"
                    + "\"policyVerdict\":\"REVIEW\",\"status\":\"PARTIAL\","
                    + "\"explanation\":[\"Unknown is not clean\"],\"errors\":[\"PE unavailable\"],"
                    + "\"correlationId\":\"c-1\","
                    + "\"explanationDetails\":{\"summary\":\"LLM summary\",\"supporting_evidence\":[\"evidence\"],"
                    + "\"uncertainties\":[\"missing signal\"],\"recommended_action\":\"Review safely\","
                    + "\"generated_by\":\"llm\",\"fallback_used\":false}}");
        });
        server.createContext("/api/v1/file-shield/settings", exchange -> {
            settingsMethod.set(exchange.getRequestMethod());
            if ("PUT".equals(exchange.getRequestMethod())) postedBody.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            respond(exchange, 200, "{\"enabled\":true,\"allowedRoots\":[\"C:/safe\"],\"watchDirectories\":[\"C:/safe\"],"
                    + "\"reputationDatabasePath\":\"C:/data/hashes.db\",\"monitoringEnabled\":true,"
                    + "\"recursiveMonitoring\":true,\"maxMonitoringDepth\":4,\"maxFileSizeBytes\":104857600,"
                    + "\"maxFilesPerDirectoryScan\":200,\"maxDirectoryDepth\":3,\"watcherActive\":true,"
                    + "\"reputationDatabaseUsable\":true,\"reputationDatabaseMessage\":\"ready\"}");
        });
        server.createContext("/api/security-events", exchange -> respond(exchange, 200,
                "[{\"id\":1,\"timestamp\":\"2026-10-01T00:00:00Z\",\"url\":\"https://example.com\","
                        + "\"phishingProbability\":0.01,\"riskScore\":1,\"riskLevel\":\"SAFE\","
                        + "\"prediction\":\"BENIGN\",\"decision\":\"ALLOW\"}]"));
        server.createContext("/api/security-events/stats", exchange -> respond(exchange, 200,
                "{\"totalEvents\":1,\"safeCount\":1,\"lowRiskCount\":0,\"suspiciousCount\":0,"
                        + "\"highRiskCount\":0,\"allowCount\":1,\"reviewCount\":0,\"warnCount\":0,"
                        + "\"blockCount\":0,\"phishingCount\":0,\"benignCount\":1}"));
        server.createContext("/api/security-events/assessments/stats", exchange -> respond(exchange, 200, assessmentStatsBody.get()));
        server.createContext("/api/security-events/assessments", exchange -> respond(exchange, 200,
                "[{\"id\":2,\"timestamp\":\"2026-10-02T00:00:00Z\",\"decision\":\"REVIEW\","
                        + "\"eventType\":\"THREAT_ASSESSMENT\",\"subjectType\":\"FILE\","
                        + "\"subjectId\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\","
                        + "\"correlationId\":\"corr-1\",\"detailsJson\":\"{\\\"assessmentId\\\":\\\"assess-1\\\",\\\"status\\\":\\\"PARTIAL\\\",\\\"sources\\\":{}}\"}]"));
        server.createContext("/api/monitor-events", exchange -> respond(exchange, 200, "{\"events\":[],\"count\":0}"));
        server.start();
        api = new ApiService("http://127.0.0.1:" + server.getAddress().getPort());
    }

    @AfterEach
    void stopServer() { if (server != null) server.stop(0); }

    @Test
    void preservesSpringAndMlHealthAsSeparateBackendValues() throws Exception {
        var health = api.getServiceHealth();
        assertTrue(health.isBackendAvailable());
        assertFalse(health.isMlAvailable());
        assertFalse(health.isFullyAvailable());
        assertEquals(503, health.httpStatus());
    }

    @Test
    void mapsExistingAnalysisHistoryAndStatsContracts() throws Exception {
        var result = api.analyzeUrl("https://example.com");
        assertEquals("SAFE", result.riskLevel());
        assertEquals("BENIGN", result.prediction());
        assertEquals("ALLOW", result.decision());
        assertTrue(postedBody.get().contains("\"url\":\"https://example.com\""));

        assertEquals(1, api.getRecentEvents().size());
        assertEquals("ALLOW", api.getRecentEvents().get(0).decision());
        assertTrue(api.getRecentMonitorEvents().isEmpty());
        assertEquals(1, api.getSecurityEventStats().totalEvents());
    }

    @Test
    void rejectsNonHttpBackendBaseAddress() {
        assertThrows(IllegalArgumentException.class, () -> new ApiService("file:///tmp/backend"));
    }

    @Test
    void sendsUnifiedFileAssessmentThroughSpringAndMapsPartialSourceResults() throws Exception {
        var result = api.assessFile("C:/approved/file.exe");
        assertEquals("REVIEW", result.policyVerdict());
        assertEquals("PARTIAL", result.status());
        assertEquals("UNKNOWN", result.sources().get("fileReputation").path("reputationStatus").asText());
        assertNotNull(result.explanationDetails());
        assertEquals("LLM summary", result.explanationDetails().summary());
        assertFalse(result.explanationDetails().fallbackUsed());
        assertTrue(postedBody.get().contains("C:/approved/file.exe"));
    }

    @Test
    void loadsBoundedAssessmentHistoryAndLifetimeAggregates() throws Exception {
        var history = api.getRecentAssessments();
        assertEquals(1, history.size());
        assertEquals("FILE", history.get(0).subjectType());
        assertEquals("corr-1", history.get(0).correlationId());
        assertTrue(history.get(0).detailsJson().contains("assess-1"));
        var stats = api.getAssessmentStats();
        assertEquals(2, stats.totalAssessments());
        assertEquals(1, stats.fileAssessments());
        assertEquals(1, stats.partialCount());
        assertEquals(1, stats.unknownReputationCount());
    }

    @Test
    void readsAndAppliesFileShieldSettingsThroughSpring() throws Exception {
        var current = api.getFileShieldSettings();
        assertTrue(current.enabled());
        assertEquals("C:/safe", current.allowedRoots().get(0));
        assertTrue(current.reputationDatabaseUsable());
        assertEquals("GET", settingsMethod.get());

        var updated = api.updateFileShieldSettings(new FileShieldSettingsUpdate(
                true, java.util.List.of("C:/safe"), java.util.List.of("C:/safe"), "C:/data/hashes.db",
                true, true, 4, 104857600, 200, 3));
        assertTrue(updated.watcherActive());
        assertEquals("PUT", settingsMethod.get());
        assertTrue(postedBody.get().contains("\"allowedRoots\":[\"C:/safe\"]"));
    }

    @Test
    void rejectsMalformedAssessmentAggregateResponse() {
        assessmentStatsBody.set("{not-json");
        assertThrows(Exception.class, api::getAssessmentStats);
    }

    private static void respond(com.sun.net.httpserver.HttpExchange exchange, int status, String body)
            throws java.io.IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        try (var output = exchange.getResponseBody()) { output.write(bytes); }
    }
}
