package com.aiwatchdog.backend.service;

import com.aiwatchdog.backend.config.MlServiceConfig;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;
import org.springframework.web.client.RestClient;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class MlServiceClientTest {
    @Test
    void parsesStructuredPeJsonFromLocalAnalyzer() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/api/analyze-file", exchange -> respond(exchange, 200,
                "{\"status\":\"ANALYZED\",\"risk_score\":10,\"sha256\":\"abc\"}"));
        server.start();
        try {
            MlServiceClient client = client(server);
            var response = client.analyzeFile("C:/approved/benign-fixture.exe");
            assertEquals("ANALYZED", response.path("status").asText());
            assertEquals(10, response.path("risk_score").asInt());
        } finally { server.stop(0); }
    }

    @Test
    void malformedPeJsonProducesExplicitMalformedResponseFailure() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/api/analyze-file", exchange -> respond(exchange, 200, "{not-json"));
        server.start();
        try {
            MlServiceException failure = assertThrows(MlServiceException.class,
                    () -> client(server).analyzeFile("C:/approved/benign-fixture.exe"));
            assertEquals(MlServiceException.FailureType.MALFORMED_RESPONSE, failure.failureType());
        } finally { server.stop(0); }
    }

    private static MlServiceClient client(HttpServer server) {
        return new MlServiceClient(RestClient.builder(),
                new MlServiceConfig("http://127.0.0.1:" + server.getAddress().getPort(), 1000, 1000));
    }

    private static void respond(com.sun.net.httpserver.HttpExchange exchange, int status, String body)
            throws java.io.IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        try (var output = exchange.getResponseBody()) { output.write(bytes); }
    }
}
