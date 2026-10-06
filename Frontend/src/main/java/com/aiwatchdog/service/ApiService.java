package com.aiwatchdog.service;

import com.aiwatchdog.model.AnalyzeRequest;
import com.aiwatchdog.model.AnalyzeResponse;
import com.aiwatchdog.model.MonitorEvent;
import com.aiwatchdog.model.SecurityEvent;
import com.aiwatchdog.model.SecurityEventStats;
import com.aiwatchdog.model.ServiceHealth;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;

/** Central JavaFX-to-Spring REST client. The desktop never calls FastAPI or SQLite directly. */
public class ApiService implements MonitorEventSubmitter {
    private static final String DEFAULT_BASE_URL = "http://127.0.0.1:8080";

    private final HttpClient httpClient;
    private final ObjectMapper mapper;
    private final String baseUrl;

    public ApiService() {
        this(System.getProperty("aiwatchdog.backend.url",
                System.getenv().getOrDefault("AI_WATCHDOG_BACKEND_URL", DEFAULT_BASE_URL)));
    }

    public ApiService(String baseUrl) {
        if (baseUrl == null || baseUrl.isBlank()) throw new IllegalArgumentException("Backend URL is required");
        String normalized = baseUrl.trim().replaceAll("/+$", "");
        URI uri = URI.create(normalized);
        if (!"http".equalsIgnoreCase(uri.getScheme()) && !"https".equalsIgnoreCase(uri.getScheme())) {
            throw new IllegalArgumentException("Backend URL must use HTTP or HTTPS");
        }
        this.baseUrl = normalized;
        this.httpClient = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build();
        this.mapper = new ObjectMapper();
    }

    public String getBaseUrl() { return baseUrl; }

    public AnalyzeResponse analyzeUrl(String url) throws Exception {
        String body = mapper.writeValueAsString(new AnalyzeRequest(url));
        HttpRequest request = HttpRequest.newBuilder()
                .uri(endpoint("/api/v1/analyze"))
                .header("Content-Type", "application/json")
                .timeout(Duration.ofSeconds(15))
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new IOException("Analysis request failed with HTTP " + response.statusCode());
        }
        return readBody(response, AnalyzeResponse.class, "Backend returned an empty analysis response");
    }

    /** Parses the response body even for HTTP 503 so Spring and ML status remain distinct. */
    public ServiceHealth getServiceHealth() throws Exception {
        HttpRequest request = HttpRequest.newBuilder().uri(endpoint("/api/v1/health"))
                .timeout(Duration.ofSeconds(5)).GET().build();
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.body() == null || response.body().isBlank()) {
            throw new IOException("Health endpoint returned no status");
        }
        var body = mapper.readTree(response.body());
        String spring = body.path("spring_boot").asText("DOWN");
        String ml = body.path("ml_service").asText("DOWN");
        return new ServiceHealth(spring, ml, response.statusCode());
    }

    public boolean isBackendHealthy() throws Exception { return getServiceHealth().isFullyAvailable(); }

    public List<SecurityEvent> getRecentEvents() throws Exception {
        return getList("/api/security-events", new TypeReference<>() {});
    }

    public List<MonitorEvent> getRecentMonitorEvents() throws Exception {
        HttpResponse<String> response = get("/api/monitor-events");
        requireSuccess(response, "Monitor history request failed");
        var body = mapper.readTree(response.body());
        return mapper.convertValue(body.path("events"), new TypeReference<List<MonitorEvent>>() {});
    }

    public SecurityEventStats getSecurityEventStats() throws Exception {
        HttpResponse<String> response = get("/api/security-events/stats");
        requireSuccess(response, "Security statistics request failed");
        return readBody(response, SecurityEventStats.class, "Backend returned no security statistics");
    }

    @Override
    public MonitorEvent submit(String eventType, String action, String resourceName,
                               Long processId, Long sizeBytes) throws Exception {
        var payload = new MonitorEventRequest(eventType, action, resourceName, processId, sizeBytes);
        HttpRequest request = HttpRequest.newBuilder().uri(endpoint("/api/monitor-events"))
                .header("Content-Type", "application/json").timeout(Duration.ofSeconds(10))
                .POST(HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(payload))).build();
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        requireSuccess(response, "Monitor event submission failed");
        return readBody(response, MonitorEvent.class, "Backend returned no monitor event");
    }

    private List<SecurityEvent> getList(String path, TypeReference<List<SecurityEvent>> type) throws Exception {
        HttpResponse<String> response = get(path);
        requireSuccess(response, "Event history request failed");
        return mapper.readValue(response.body(), type);
    }

    private HttpResponse<String> get(String path) throws Exception {
        HttpRequest request = HttpRequest.newBuilder().uri(endpoint(path)).timeout(Duration.ofSeconds(5)).GET().build();
        return httpClient.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private URI endpoint(String path) { return URI.create(baseUrl + path); }

    private static void requireSuccess(HttpResponse<String> response, String message) throws IOException {
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new IOException(message + " (HTTP " + response.statusCode() + ")");
        }
    }

    private <T> T readBody(HttpResponse<String> response, Class<T> type, String message) throws IOException {
        if (response.body() == null || response.body().isBlank()) throw new IOException(message);
        return mapper.readValue(response.body(), type);
    }

    private record MonitorEventRequest(String eventType, String action, String resourceName,
                                       Long processId, Long sizeBytes) { }
}
