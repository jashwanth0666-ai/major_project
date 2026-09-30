package com.aiwatchdog.service;

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
        server.createContext("/api/security-events", exchange -> respond(exchange, 200,
                "[{\"id\":1,\"timestamp\":\"2026-10-01T00:00:00Z\",\"url\":\"https://example.com\","
                        + "\"phishingProbability\":0.01,\"riskScore\":1,\"riskLevel\":\"SAFE\","
                        + "\"prediction\":\"BENIGN\",\"decision\":\"ALLOW\"}]"));
        server.createContext("/api/security-events/stats", exchange -> respond(exchange, 200,
                "{\"totalEvents\":1,\"safeCount\":1,\"lowRiskCount\":0,\"suspiciousCount\":0,"
                        + "\"highRiskCount\":0,\"allowCount\":1,\"reviewCount\":0,\"warnCount\":0,"
                        + "\"blockCount\":0,\"phishingCount\":0,\"benignCount\":1}"));
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

    private static void respond(com.sun.net.httpserver.HttpExchange exchange, int status, String body)
            throws java.io.IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        try (var output = exchange.getResponseBody()) { output.write(bytes); }
    }
}
