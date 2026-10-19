package com.aiwatchdog.backend.assessment;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.net.URLEncoder;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/** Optional hostname provider or explicitly selected URL-level threat-intelligence provider. */
@Component
public class ConfiguredUrlReputationService implements UrlReputationService {
    private static final String GOOGLE_SAFE_BROWSING_V5 = "google-safe-browsing-v5";
    private static final int MAX_BODY = 8192;
    private final boolean enabled;
    private final String endpoint;
    private final String apiKey;
    private final String provider;
    private final int timeoutMs;
    private final int cacheTtlSeconds;
    private final int requestsPerMinute;
    private final HttpClient client;
    private final ObjectMapper mapper = new ObjectMapper();
    private final Map<String, Cached> cache = new LinkedHashMap<>(128, .75f, true) {
        @Override protected boolean removeEldestEntry(Map.Entry<String, Cached> eldest) { return size() > 2000; }
    };
    private long rateWindow = -1;
    private int requestCount;

    public ConfiguredUrlReputationService(boolean enabled, String endpoint, String apiKey,
                                          String provider, int timeoutMs, int requestsPerMinute) {
        this(enabled, endpoint, apiKey, provider, timeoutMs, 300, requestsPerMinute);
    }

    @Autowired
    public ConfiguredUrlReputationService(
            @Value("${ai-watchdog.url-reputation.enabled:false}") boolean enabled,
            @Value("${ai-watchdog.url-reputation.endpoint:}") String endpoint,
            @Value("${ai-watchdog.url-reputation.api-key:}") String apiKey,
            @Value("${ai-watchdog.url-reputation.provider:configured-url-provider}") String provider,
            @Value("${ai-watchdog.url-reputation.timeout-ms:3000}") int timeoutMs,
            @Value("${ai-watchdog.url-reputation.cache-ttl-seconds:300}") int cacheTtlSeconds,
            @Value("${ai-watchdog.url-reputation.requests-per-minute:30}") int requestsPerMinute) {
        this.enabled = enabled;
        this.endpoint = endpoint == null ? "" : endpoint.trim();
        this.apiKey = apiKey == null ? "" : apiKey;
        this.provider = provider == null || provider.isBlank() ? "configured-url-provider" : provider.trim();
        this.timeoutMs = Math.max(250, Math.min(timeoutMs, 10000));
        this.cacheTtlSeconds = Math.max(1, Math.min(cacheTtlSeconds, 86400));
        this.requestsPerMinute = Math.max(1, Math.min(requestsPerMinute, 600));
        this.client = HttpClient.newBuilder().connectTimeout(Duration.ofMillis(this.timeoutMs))
                .followRedirects(HttpClient.Redirect.NEVER).build();
    }

    @Override public UrlReputationResult lookup(String host) {
        String normalized = normalize(host);
        if (normalized == null) return result("UNAVAILABLE", null, null, "URL host is invalid.");
        if (!enabled) return UrlReputationResult.disabled(normalized);
        if (GOOGLE_SAFE_BROWSING_V5.equalsIgnoreCase(provider))
            return result("UNAVAILABLE", normalized, null, "Google Safe Browsing v5 needs a sanitized full URL; host-only lookup is unsupported.");
        return lookupHost(normalized);
    }

    @Override public UrlReputationResult lookupUrl(String url, String host) {
        String normalized = normalize(host);
        if (normalized == null) return result("UNAVAILABLE", null, null, "URL host is invalid.");
        if (!enabled) return UrlReputationResult.disabled(normalized);
        if (!GOOGLE_SAFE_BROWSING_V5.equalsIgnoreCase(provider)) return lookupHost(normalized);
        return lookupGoogleSafeBrowsing(url, normalized);
    }

    private UrlReputationResult lookupHost(String normalized) {
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

    private UrlReputationResult lookupGoogleSafeBrowsing(String sanitizedUrl, String host) {
        if (apiKey.isBlank()) return result("UNAVAILABLE", host, null, "Google Safe Browsing v5 API key is not configured.");
        final String canonicalUrl;
        try {
            URI parsed = URI.create(sanitizedUrl);
            if (!("http".equalsIgnoreCase(parsed.getScheme()) || "https".equalsIgnoreCase(parsed.getScheme()))
                    || parsed.getHost() == null || parsed.getUserInfo() != null || parsed.getQuery() != null
                    || parsed.getFragment() != null || sanitizedUrl.length() > 4096)
                return result("UNAVAILABLE", host, null, "URL is invalid or was not sanitized for reputation lookup.");
            canonicalUrl = parsed.toASCIIString();
        } catch (RuntimeException invalid) {
            return result("UNAVAILABLE", host, null, "URL is invalid or was not sanitized for reputation lookup.");
        }
        String cacheKey = "google:" + canonicalUrl;
        synchronized (cache) {
            Cached cached = cache.get(cacheKey);
            if (cached != null && cached.expiresAt.isAfter(Instant.now()))
                return new UrlReputationResult(cached.result.status(), cached.result.provider(), host,
                        cached.result.checkedAt(), cached.result.observedAt(),
                        Math.max(0, Duration.between(cached.createdAt, Instant.now()).toSeconds()),
                        "Cached Google Safe Browsing v5 URL result; query, user info, and fragment were omitted.");
            cache.remove(cacheKey);
        }
        synchronized (this) {
            long currentWindow = System.currentTimeMillis() / 60_000;
            if (currentWindow != rateWindow) { rateWindow = currentWindow; requestCount = 0; }
            if (requestCount >= requestsPerMinute)
                return result("UNAVAILABLE", host, null, "Local provider request limit was reached.");
            requestCount++;
        }
        try {
            String query = "urls=" + URLEncoder.encode(canonicalUrl, StandardCharsets.UTF_8);
            URI target = URI.create("https://safebrowsing.googleapis.com/v5/urls:search?" + query);
            HttpRequest request = HttpRequest.newBuilder(target).timeout(Duration.ofMillis(timeoutMs))
                    .header("Accept", "application/json").header("X-Goog-Api-Key", apiKey).GET().build();
            HttpResponse<java.io.InputStream> response = client.send(request, HttpResponse.BodyHandlers.ofInputStream());
            byte[] responseBytes;
            if (response.body() == null) responseBytes = new byte[0];
            else try (var bodyStream = response.body()) { responseBytes = bodyStream.readNBytes(MAX_BODY + 1); }
            if (response.statusCode() == 429) return result("UNAVAILABLE", host, null, "Provider rate limit was reached.");
            if (response.statusCode() < 200 || response.statusCode() >= 300)
                return result("UNAVAILABLE", host, null, "Google Safe Browsing v5 returned an unavailable response.");
            if (responseBytes.length == 0 || responseBytes.length > MAX_BODY)
                return result("UNAVAILABLE", host, null, "Provider response was empty or exceeded its size limit.");
            var json = mapper.readTree(responseBytes);
            var threats = json.path("threats");
            if (!threats.isMissingNode() && !threats.isArray())
                return result("UNAVAILABLE", host, null, "Provider response did not contain a valid threat list.");
            boolean malicious = false;
            if (threats.isArray()) for (var threat : threats) {
                var threatTypes = threat.path("threatTypes");
                if (!threat.isObject() || !threatTypes.isArray() || threatTypes.isEmpty())
                    return result("UNAVAILABLE", host, null, "Provider response contained an invalid threat entry.");
                for (var type : threatTypes) {
                    if (!type.isTextual() || type.asText().isBlank())
                        return result("UNAVAILABLE", host, null, "Provider response contained an invalid threat type.");
                }
                malicious = true;
            }
            String status = malicious ? "KNOWN_MALICIOUS" : "UNKNOWN";
            long ttl = parseCacheDuration(json.path("cacheDuration").asText(null));
            return cacheWithTtl(cacheKey, host, status, null, malicious
                    ? "Google Safe Browsing v5 matched the sanitized URL; query, user info, and fragment were omitted."
                    : "Google Safe Browsing v5 found no known threat for the sanitized URL; this is not proof the URL is safe. Query, user info, and fragment were omitted.", ttl);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            return result("UNAVAILABLE", host, null, "Provider lookup was interrupted.");
        } catch (Exception failure) {
            return result("UNAVAILABLE", host, null, failure instanceof java.net.http.HttpTimeoutException
                    ? "Provider lookup timed out." : "Provider could not be reached.");
        }
    }

    private UrlReputationResult cache(String host, String status, String observedAt, String detail) {
        UrlReputationResult value = result(status, host, observedAt, detail);
        synchronized (cache) { cache.put(host, new Cached(value, Instant.now(), Instant.now().plusSeconds(cacheTtlSeconds))); }
        return value;
    }
    private UrlReputationResult cacheWithTtl(String cacheKey, String host, String status, String observedAt,
                                             String detail, long ttlSeconds) {
        Instant now = Instant.now();
        UrlReputationResult value = result(status, host, observedAt, detail);
        synchronized (cache) { cache.put(cacheKey, new Cached(value, now, now.plusSeconds(ttlSeconds))); }
        return value;
    }
    private long parseCacheDuration(String value) {
        if (value == null || !value.matches("[0-9]+(?:\\.[0-9]{1,9})?s")) return cacheTtlSeconds;
        try {
            double seconds = Double.parseDouble(value.substring(0, value.length() - 1));
            return Math.max(1, Math.min(86400, (long) Math.ceil(seconds)));
        } catch (RuntimeException invalid) { return cacheTtlSeconds; }
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
