package com.aiwatchdog.backend.assessment;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/** Optional hostname-only provider. Its configured endpoint must implement the documented JSON contract. */
@Component
public class ConfiguredUrlReputationService implements UrlReputationService {
    private static final int MAX_BODY = 8192;
    private final boolean enabled;
    private final String endpoint;
    private final String apiKey;
    private final String provider;
    private final int timeoutMs;
    private final int requestsPerMinute;
    private final HttpClient client;
    private final ObjectMapper mapper = new ObjectMapper();
    private final Map<String, Cached> cache = new LinkedHashMap<>(128, .75f, true) {
        @Override protected boolean removeEldestEntry(Map.Entry<String, Cached> eldest) { return size() > 2000; }
    };
    private long rateWindow = -1;
    private int requestCount;

    public ConfiguredUrlReputationService(
            @Value("${ai-watchdog.url-reputation.enabled:false}") boolean enabled,
            @Value("${ai-watchdog.url-reputation.endpoint:}") String endpoint,
            @Value("${ai-watchdog.url-reputation.api-key:}") String apiKey,
            @Value("${ai-watchdog.url-reputation.provider:configured-url-provider}") String provider,
            @Value("${ai-watchdog.url-reputation.timeout-ms:3000}") int timeoutMs,
            @Value("${ai-watchdog.url-reputation.requests-per-minute:30}") int requestsPerMinute) {
        this.enabled = enabled;
        this.endpoint = endpoint == null ? "" : endpoint.trim();
        this.apiKey = apiKey == null ? "" : apiKey;
        this.provider = provider == null || provider.isBlank() ? "configured-url-provider" : provider.trim();
        this.timeoutMs = Math.max(250, Math.min(timeoutMs, 10000));
        this.requestsPerMinute = Math.max(1, Math.min(requestsPerMinute, 600));
        this.client = HttpClient.newBuilder().connectTimeout(Duration.ofMillis(this.timeoutMs))
                .followRedirects(HttpClient.Redirect.NEVER).build();
    }

    @Override public UrlReputationResult lookup(String host) {
        String normalized = normalize(host);
        if (normalized == null) return result("UNAVAILABLE", null, null, "URL host is invalid.");
        if (!enabled) return UrlReputationResult.disabled(normalized);
        URI target = endpoint();
        if (target == null) return result("UNAVAILABLE", normalized, null, "Provider is not configured with a valid HTTPS endpoint.");
        synchronized (cache) {
            Cached cached = cache.get(normalized);
            if (cached != null && cached.expiresAt.isAfter(Instant.now()))
                return new UrlReputationResult(cached.result.status(), cached.result.provider(), normalized,
                        cached.result.checkedAt(), cached.result.observedAt(),
                        Math.max(0, Duration.between(cached.createdAt, Instant.now()).toSeconds()), "Cached provider response.");
            cache.remove(normalized);
        }
        synchronized (this) {
            long currentWindow = System.currentTimeMillis() / 60_000;
            if (currentWindow != rateWindow) { rateWindow = currentWindow; requestCount = 0; }
            if (requestCount >= requestsPerMinute)
                return result("UNAVAILABLE", normalized, null, "Local provider request limit was reached.");
            requestCount++;
        }
        try {
            byte[] body = mapper.writeValueAsBytes(Map.of("host", normalized));
            HttpRequest.Builder request = HttpRequest.newBuilder(target).timeout(Duration.ofMillis(timeoutMs))
                    .header("Accept", "application/json").header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofByteArray(body));
            if (!apiKey.isBlank()) request.header("X-Api-Key", apiKey);
            HttpResponse<java.io.InputStream> response = client.send(request.build(), HttpResponse.BodyHandlers.ofInputStream());
            byte[] responseBytes = new byte[0];
            if (response.body() != null) {
                try (var bodyStream = response.body()) { responseBytes = bodyStream.readNBytes(MAX_BODY + 1); }
            }
            if (response.statusCode() == 404 || response.statusCode() == 204)
                return cache(normalized, "UNKNOWN", null, "Provider has no record for this host.");
            if (response.statusCode() == 429) return result("UNAVAILABLE", normalized, null, "Provider rate limit was reached.");
            if (response.statusCode() < 200 || response.statusCode() >= 300)
                return result("UNAVAILABLE", normalized, null, "Provider returned an unavailable response.");
            if (responseBytes.length == 0 || responseBytes.length > MAX_BODY)
                return result("UNAVAILABLE", normalized, null, "Provider response was empty or exceeded its size limit.");
            var json = mapper.readTree(responseBytes);
            String status = json.path("reputation").asText("").trim().toUpperCase(Locale.ROOT);
            if (!switch (status) { case "KNOWN_MALICIOUS", "KNOWN_CLEAN", "SUSPICIOUS", "UNKNOWN" -> true; default -> false; })
                return result("UNAVAILABLE", normalized, null, "Provider returned an unsupported reputation state.");
            String observedAt = json.path("observed_at").asText(null);
            if (observedAt != null) {
                try { observedAt = Instant.parse(observedAt).toString(); }
                catch (RuntimeException invalidTime) { return result("UNAVAILABLE", normalized, null, "Provider observation timestamp is invalid."); }
            }
            return cache(normalized, status, observedAt, "Provider response received.");
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            return result("UNAVAILABLE", normalized, null, "Provider lookup was interrupted.");
        } catch (Exception failure) {
            return result("UNAVAILABLE", normalized, null, failure instanceof java.net.http.HttpTimeoutException
                    ? "Provider lookup timed out." : "Provider could not be reached.");
        }
    }

    private UrlReputationResult cache(String host, String status, String observedAt, String detail) {
        UrlReputationResult value = result(status, host, observedAt, detail);
        synchronized (cache) { cache.put(host, new Cached(value, Instant.now(), Instant.now().plusSeconds(300))); }
        return value;
    }
    private UrlReputationResult result(String status, String host, String observedAt, String detail) {
        return new UrlReputationResult(status, provider, host, Instant.now().toString(), observedAt, null, detail);
    }
    private URI endpoint() {
        try {
            URI uri = URI.create(endpoint);
            return "https".equalsIgnoreCase(uri.getScheme()) && uri.getHost() != null
                    && uri.getUserInfo() == null && uri.getQuery() == null && uri.getFragment() == null ? uri : null;
        } catch (RuntimeException invalid) { return null; }
    }
    private String normalize(String value) {
        if (value == null || value.isBlank()) return null;
        try {
            String ascii = java.net.IDN.toASCII(value.trim().toLowerCase(Locale.ROOT), java.net.IDN.USE_STD3_ASCII_RULES);
            if (ascii.length() > 253 || ascii.isBlank()) return null;
            return ascii.endsWith(".") ? ascii.substring(0, ascii.length() - 1) : ascii;
        } catch (IllegalArgumentException invalid) { return null; }
    }
    private record Cached(UrlReputationResult result, Instant createdAt, Instant expiresAt) { }
}
