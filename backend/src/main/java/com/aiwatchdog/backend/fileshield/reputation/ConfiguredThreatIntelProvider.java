package com.aiwatchdog.backend.fileshield.reputation;

import com.aiwatchdog.backend.fileshield.config.FileShieldProperties;
import com.aiwatchdog.backend.fileshield.model.ReputationStatus;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

/** Optional hash-only HTTPS lookup. Disabled unless explicitly enabled and configured. */
@Component
public class ConfiguredThreatIntelProvider {
    private static final Pattern SHA256 = Pattern.compile("[a-fA-F0-9]{64}");
    private static final int MAX_CACHE_ENTRIES = 5000;
    private final FileShieldProperties properties;
    private final HttpClient client;
    private final ObjectMapper mapper = new ObjectMapper();
    private final LinkedHashMap<String, Cached> cache = new LinkedHashMap<>(256, 0.75f, true);
    private long rateWindowStart;
    private int requestsInWindow;
    private volatile Instant lastCheckedAt;
    private volatile String lastState = "CONFIGURED";
    private volatile String lastError;
    private volatile Instant retryAfter;

    public ConfiguredThreatIntelProvider(FileShieldProperties properties) {
        this.properties = properties;
        this.client = HttpClient.newBuilder().connectTimeout(Duration.ofMillis(properties.getThreatIntelTimeoutMs())).build();
    }

    public HashReputation lookup(String sha256) {
        if (sha256 == null || !SHA256.matcher(sha256).matches())
            return new HashReputation(ReputationStatus.LOOKUP_ERROR, "configured-threat-intel", "A valid SHA-256 digest is required.");
        if (!properties.isThreatIntelEnabled()) return new HashReputation(ReputationStatus.UNKNOWN, "threat-intel-disabled", "Optional threat-intelligence lookup is disabled.");
        URI endpoint = endpointFor(sha256);
        if (endpoint == null) return failure("THREAT_INTEL_NOT_CONFIGURED", "Optional threat-intelligence provider is not configured.");
        Cached cached = cached(sha256);
        if (cached != null) return cached.value;
        synchronized (this) {
            Instant retry = retryAfter;
            if (retry != null && Instant.now().isBefore(retry)) return failure("RATE_LIMITED", "Threat-intelligence provider rate limit is active.");
            if (!takeRateToken()) return failure("LOCAL_RATE_LIMIT", "Configured threat-intelligence request limit was reached.");
        }
        try {
            HttpRequest.Builder request = HttpRequest.newBuilder(endpoint)
                    .timeout(Duration.ofMillis(properties.getThreatIntelTimeoutMs())).GET()
                    .header("Accept", "application/json");
            String key = properties.getThreatIntelApiKey();
            if (key != null && !key.isBlank()) request.header("X-Api-Key", key);
            HttpResponse<String> response = client.send(request.build(), HttpResponse.BodyHandlers.ofString(java.nio.charset.StandardCharsets.UTF_8));
            lastCheckedAt = Instant.now();
            if (response.statusCode() == 404 || response.statusCode() == 204) {
                lastState = "READY"; lastError = null;
                return cache(sha256, new HashReputation(ReputationStatus.UNKNOWN, "configured-threat-intel", "Provider has no hash record."));
            }
            if (response.statusCode() == 429) {
                long retrySeconds = response.headers().firstValue("Retry-After").map(this::parseRetryAfter).orElse(60L);
                retryAfter = Instant.now().plusSeconds(Math.min(300, Math.max(1, retrySeconds)));
                return failure("RATE_LIMITED", "Threat-intelligence provider rate limit was reached.");
            }
            if (response.statusCode() < 200 || response.statusCode() >= 300)
                return failure("HTTP_" + response.statusCode(), "Threat-intelligence provider returned an unavailable response.");
            if (response.body() == null || response.body().length() > 8192)
                return failure("INVALID_RESPONSE", "Threat-intelligence response was empty or exceeded its size limit.");
            var json = mapper.readTree(response.body());
            ReputationStatus status = parseStatus(json.path("reputation").asText(""));
            if (status == null) return failure("INVALID_RESPONSE", "Threat-intelligence response contained an unsupported reputation state.");
            String description = bounded(json.path("description").asText(null), 512);
            lastState = "READY"; lastError = null; retryAfter = null;
            return cache(sha256, new HashReputation(status, "configured-threat-intel", description));
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            return failure("INTERRUPTED", "Threat-intelligence lookup was interrupted.");
        } catch (IOException | RuntimeException exception) {
            return failure(exception instanceof java.net.http.HttpTimeoutException ? "TIMEOUT" : "NETWORK_ERROR",
                    "Threat-intelligence provider could not be reached.");
        }
    }

    public ReputationProviderStatus health() {
        if (!properties.isThreatIntelEnabled()) return new ReputationProviderStatus("configured-threat-intel", "DISABLED", null, lastCheckedAt);
        if (endpointFor("0".repeat(64)) == null) return new ReputationProviderStatus("configured-threat-intel", "UNAVAILABLE", "THREAT_INTEL_NOT_CONFIGURED", lastCheckedAt);
        Instant retry = retryAfter;
        String state = retry != null && Instant.now().isBefore(retry) ? "RATE_LIMITED" : lastState;
        return new ReputationProviderStatus("configured-threat-intel", state, lastError, lastCheckedAt);
    }

    private URI endpointFor(String hash) {
        if (hash == null || !SHA256.matcher(hash).matches()) return null;
        String configured = properties.getThreatIntelEndpoint();
        if (configured == null || configured.isBlank()) return null;
        try {
            URI base = URI.create(configured.trim());
            if (!"https".equalsIgnoreCase(base.getScheme()) || base.getHost() == null
                    || base.getUserInfo() != null || base.getFragment() != null || base.getQuery() != null) return null;
            String value = base.toString().replaceAll("/+$", "");
            return URI.create(value + "/" + hash.toLowerCase(Locale.ROOT));
        } catch (IllegalArgumentException invalid) { return null; }
    }

    private synchronized Cached cached(String hash) {
        Instant now = Instant.now();
        cache.entrySet().removeIf(entry -> entry.getValue().expiresAt.isBefore(now));
        return cache.get(hash.toLowerCase(Locale.ROOT));
    }

    private synchronized HashReputation cache(String hash, HashReputation value) {
        cache.put(hash.toLowerCase(Locale.ROOT), new Cached(value, Instant.now().plusSeconds(properties.getThreatIntelCacheTtlSeconds())));
        while (cache.size() > MAX_CACHE_ENTRIES) cache.remove(cache.keySet().iterator().next());
        return value;
    }

    private synchronized boolean takeRateToken() {
        long current = System.currentTimeMillis() / 60_000;
        if (current != rateWindowStart) { rateWindowStart = current; requestsInWindow = 0; }
        if (requestsInWindow >= properties.getThreatIntelRequestsPerMinute()) return false;
        requestsInWindow++;
        return true;
    }

    private ReputationStatus parseStatus(String value) {
        return switch (value.trim().toUpperCase(Locale.ROOT)) {
            case "KNOWN_MALICIOUS" -> ReputationStatus.KNOWN_MALICIOUS;
            case "KNOWN_CLEAN", "KNOWN_TRUSTED" -> ReputationStatus.KNOWN_CLEAN;
            case "SUSPICIOUS" -> ReputationStatus.SUSPICIOUS;
            case "UNKNOWN" -> ReputationStatus.UNKNOWN;
            default -> null;
        };
    }

    private long parseRetryAfter(String value) {
        try { return Long.parseLong(value.trim()); }
        catch (NumberFormatException ignored) { return 60; }
    }

    private HashReputation failure(String category, String message) {
        lastState = "DEGRADED"; lastError = category;
        return new HashReputation(ReputationStatus.LOOKUP_ERROR, "configured-threat-intel", message);
    }

    private String bounded(String value, int max) {
        if (value == null || value.isBlank()) return null;
        return value.length() <= max ? value : value.substring(0, max);
    }

    private record Cached(HashReputation value, Instant expiresAt) { }
}
