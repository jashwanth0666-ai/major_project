package com.aiwatchdog.service;

import com.aiwatchdog.model.AnalyzeRequest;
import com.aiwatchdog.model.AnalyzeResponse;
import com.aiwatchdog.model.AssessmentStats;
import com.aiwatchdog.model.FileShieldDirectoryResult;
import com.aiwatchdog.model.FileShieldSettings;
import com.aiwatchdog.model.FileShieldSettingsUpdate;
import com.aiwatchdog.model.FileShieldScanRequest;
import com.aiwatchdog.model.FileShieldScanResult;
import com.aiwatchdog.model.MonitorEvent;
import com.aiwatchdog.model.SecurityEvent;
import com.aiwatchdog.model.SecurityEventStats;
import com.aiwatchdog.model.ServiceHealth;
import com.aiwatchdog.model.ThreatAssessmentResult;
import com.aiwatchdog.model.ThreatAssessmentExplanation;
import com.aiwatchdog.model.AiInsightsResponse;
import com.aiwatchdog.model.ApiPermissionCapabilities;
import com.aiwatchdog.model.NotificationPreferences;
import com.aiwatchdog.model.WindowsTelemetryHealth;
import com.aiwatchdog.model.WindowsTelemetrySettings;
import com.aiwatchdog.model.WindowsTelemetrySettingsUpdate;
import com.aiwatchdog.model.QuarantineHistory;
import com.aiwatchdog.model.QuarantineOperation;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;

/** Central JavaFX-to-Spring REST client. The desktop never calls FastAPI or SQLite directly. */
public class ApiService implements MonitorEventSubmitter {
    private static final String DEFAULT_BASE_URL = "http://127.0.0.1:8080";

    private final HttpClient httpClient;
    private final ObjectMapper mapper;
    private final String baseUrl;
    private final String localToken;

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
        this.localToken = loadLocalToken();
    }

    public String getBaseUrl() { return baseUrl; }
    public boolean hasLocalDesktopCredential() { return localToken != null; }

    public AnalyzeResponse analyzeUrl(String url) throws Exception {
        String body = mapper.writeValueAsString(new AnalyzeRequest(url));
        HttpRequest request = authorizedRequest("/api/v1/analyze")
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

    public void submitThreatFeedback(AnalyzeResponse assessment, String label) throws Exception {
        if (assessment == null || assessment.assessmentId() == null || assessment.correlationId() == null) {
            throw new IllegalArgumentException("This assessment cannot be linked to feedback.");
        }
        if (!List.of("FALSE_POSITIVE", "FALSE_NEGATIVE", "CORRECT").contains(label)) {
            throw new IllegalArgumentException("Unsupported feedback label.");
        }
        postJson("/api/v1/threat-assessments/feedback",
                new ThreatFeedbackRequest(assessment.assessmentId(), assessment.correlationId(), label), JsonNode.class);
    }

    /** Performs one read-only file scan. Call from a background Task, never the FX thread. */
    public FileShieldScanResult scanFile(String path) throws Exception {
        return postJson("/api/v1/file-shield/scan", new FileShieldScanRequest(path), FileShieldScanResult.class);
    }

    /** Performs a bounded directory scan. Call from a background Task, never the FX thread. */
    public FileShieldDirectoryResult scanDirectory(String path) throws Exception {
        return postJson("/api/v1/file-shield/scan-directory", new FileShieldScanRequest(path), FileShieldDirectoryResult.class);
    }

    public FileShieldSettings getFileShieldSettings() throws Exception {
        HttpResponse<String> response = get("/api/v1/file-shield/settings");
        requireSuccess(response, "File Shield settings request failed");
        return readBody(response, FileShieldSettings.class, "Backend returned no File Shield settings");
    }

    public FileShieldSettings updateFileShieldSettings(FileShieldSettingsUpdate settings) throws Exception {
        return postJson("/api/v1/file-shield/settings", settings, FileShieldSettings.class, "PUT");
    }

    public QuarantineHistory getQuarantineHistory() throws Exception {
        HttpResponse<String> response = get("/api/v1/file-shield/quarantine");
        requireSuccess(response, "Quarantine history request failed");
        return readBody(response, QuarantineHistory.class, "Backend returned no quarantine history");
    }

    public QuarantineOperation quarantineFile(String path, String sha256) throws Exception {
        return postJson("/api/v1/file-shield/quarantine", new QuarantineRequest(path, sha256, true), QuarantineOperation.class);
    }

    public QuarantineOperation restoreQuarantinedFile(String operationId, String destinationPath, boolean reinspect) throws Exception {
        return postJson("/api/v1/file-shield/quarantine/" + java.net.URLEncoder.encode(operationId, java.nio.charset.StandardCharsets.UTF_8)
                + "/restore", new RestoreRequest(destinationPath, true, reinspect), QuarantineOperation.class);
    }

    public NotificationPreferences getNotificationPreferences() throws Exception {
        HttpResponse<String> response = get("/api/v1/notifications/preferences");
        requireSuccess(response, "Notification preferences request failed");
        return readBody(response, NotificationPreferences.class, "Backend returned no notification preferences");
    }

    public NotificationPreferences updateNotificationPreferences(NotificationPreferences preferences) throws Exception {
        return postJson("/api/v1/notifications/preferences", preferences, NotificationPreferences.class, "PUT");
    }

    public WindowsTelemetrySettings getWindowsTelemetrySettings() throws Exception {
        HttpResponse<String> response = get("/api/v1/windows-telemetry/settings");
        requireSuccess(response, "Windows telemetry settings request failed");
        return readBody(response, WindowsTelemetrySettings.class, "Backend returned no Windows telemetry settings");
    }

    public WindowsTelemetrySettings updateWindowsTelemetrySettings(WindowsTelemetrySettingsUpdate settings) throws Exception {
        return postJson("/api/v1/windows-telemetry/settings", settings, WindowsTelemetrySettings.class, "PUT");
    }

    public WindowsTelemetryHealth getWindowsTelemetryHealth() throws Exception {
        HttpResponse<String> response = get("/api/v1/windows-telemetry/health");
        requireSuccess(response, "Windows telemetry health request failed");
        return readBody(response, WindowsTelemetryHealth.class, "Backend returned no Windows telemetry health");
    }

    public List<String> getDomainWhitelist() throws Exception {
        HttpResponse<String> response = get("/api/v1/domain-whitelist");
        requireSuccess(response, "Domain whitelist request failed");
        return mapper.readValue(response.body(), new TypeReference<List<String>>() {});
    }

    public List<String> addDomainWhitelistEntry(String domain) throws Exception {
        return postJson("/api/v1/domain-whitelist", new DomainWhitelistRequest(domain),
                mapper.getTypeFactory().constructCollectionType(List.class, String.class));
    }

    public List<String> removeDomainWhitelistEntry(String domain) throws Exception {
        String encoded = java.net.URLEncoder.encode(domain, java.nio.charset.StandardCharsets.UTF_8).replace("+", "%20");
        HttpRequest request = authorizedRequest("/api/v1/domain-whitelist/" + encoded)
                .timeout(Duration.ofSeconds(10)).DELETE().build();
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        requireSuccess(response, "Could not remove domain exception");
        return mapper.readValue(response.body(), new TypeReference<List<String>>() {});
    }

    /** Runs reputation, PE analysis, deterministic policy, and audit integration on Spring's worker thread. */
    public ThreatAssessmentResult assessFile(String path) throws Exception {
        return postJson("/api/v1/threat-assessments/file", new ThreatAssessmentRequest(path), ThreatAssessmentResult.class);
    }

    /** Parses the response body even for HTTP 503 so Spring and ML status remain distinct. */
    public ServiceHealth getServiceHealth() throws Exception {
        HttpRequest request = authorizedRequest("/api/v1/health")
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

    /** Returns only the latest bounded assessment page exposed by Spring. */
    public List<SecurityEvent> getRecentAssessments() throws Exception {
        return getList("/api/security-events/assessments", new TypeReference<>() {});
    }

    /** Returns recent user labels for manual false-positive and missed-phishing review. */
    public List<SecurityEvent> getRecentFeedback() throws Exception {
        return getList("/api/security-events/feedback", new TypeReference<>() {});
    }

    /** Returns lifetime SQL aggregates for persisted unified assessments. */
    public AssessmentStats getAssessmentStats() throws Exception {
        HttpResponse<String> response = get("/api/security-events/assessments/stats");
        requireSuccess(response, "Assessment statistics request failed");
        return readBody(response, AssessmentStats.class, "Backend returned no assessment statistics");
    }

    public AiInsightsResponse getAiInsights(String period) throws Exception {
        String encoded = java.net.URLEncoder.encode(period, java.nio.charset.StandardCharsets.UTF_8);
        HttpResponse<String> response = get("/api/v1/threat-assessments/insights?period=" + encoded);
        requireSuccess(response, "AI insights request failed");
        return readBody(response, AiInsightsResponse.class, "Backend returned no AI insights");
    }

    public ApiPermissionCapabilities getPermissionCapabilities() throws Exception {
        HttpResponse<String> response = get("/api/v1/security/permissions");
        requireSuccess(response, "Permission capability request failed");
        return readBody(response, ApiPermissionCapabilities.class, "Backend returned no permission capabilities");
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
        HttpRequest request = authorizedRequest("/api/monitor-events")
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
        HttpRequest request = authorizedRequest(path).timeout(Duration.ofSeconds(5)).GET().build();
        return httpClient.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private <T> T postJson(String path, Object payload, Class<T> responseType) throws Exception {
        return postJson(path, payload, responseType, "POST");
    }

    private <T> T postJson(String path, Object payload, Class<T> responseType, String method) throws Exception {
        HttpRequest request = authorizedRequest(path)
                .header("Content-Type", "application/json")
                .timeout("PUT".equals(method) ? Duration.ofSeconds(15) : Duration.ofMinutes(30))
                .method(method, HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(payload)))
                .build();
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            String message = "Backend request failed (HTTP " + response.statusCode() + ")";
            if (response.body() != null && !response.body().isBlank()) {
                try {
                    String serverMessage = mapper.readTree(response.body()).path("message").asText();
                    if (!serverMessage.isBlank()) message = serverMessage;
                } catch (IOException ignored) { }
            }
            throw new IOException(message);
        }
        if (response.body() == null || response.body().isBlank()) throw new IOException("Backend returned no response body");
        return mapper.readValue(response.body(), responseType);
    }

    private <T> T postJson(String path, Object payload, com.fasterxml.jackson.databind.JavaType responseType) throws Exception {
        HttpRequest request = authorizedRequest(path).header("Content-Type", "application/json")
                .timeout(Duration.ofSeconds(10)).POST(HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(payload))).build();
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        requireSuccess(response, "Could not save domain exception");
        return mapper.readValue(response.body(), responseType);
    }

    private URI endpoint(String path) { return URI.create(baseUrl + path); }

    private HttpRequest.Builder authorizedRequest(String path) {
        HttpRequest.Builder builder = HttpRequest.newBuilder().uri(endpoint(path));
        if (localToken != null) builder.header("Authorization", "Bearer " + localToken);
        return builder;
    }

    private String loadLocalToken() {
        try {
            String configured = System.getenv("AI_WATCHDOG_TOKEN_FILE");
            Path tokenFile;
            if (configured != null && !configured.isBlank()) tokenFile = Path.of(configured).toAbsolutePath().normalize();
            else {
                String appData = System.getenv("APPDATA");
                tokenFile = appData != null && !appData.isBlank()
                        ? Path.of(appData, "AIWatchDog", "auth", "api-tokens.json")
                        : Path.of(System.getProperty("user.home"), ".aiwatchdog", "api-tokens.json");
            }
            var token = mapper.readTree(Files.readString(tokenFile)).path("desktop");
            String value = token.isTextual() ? token.asText().trim() : "";
            return value.matches("(?i)[a-f0-9]{64,}") ? value : null;
        } catch (Exception ignored) {
            return null;
        }
    }

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
    private record DomainWhitelistRequest(String domain) { }
    private record ThreatAssessmentRequest(String path) { }
    private record ThreatFeedbackRequest(String assessmentId, String correlationId, String label) { }
    private record QuarantineRequest(String path, String expectedSha256, boolean confirmed) { }
    private record RestoreRequest(String destinationPath, boolean confirmed, boolean reinspect) { }
}
