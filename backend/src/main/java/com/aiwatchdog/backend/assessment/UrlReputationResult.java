package com.aiwatchdog.backend.assessment;

import java.time.Instant;

/** URL reputation evidence; unavailable and unknown are deliberately distinct. */
public record UrlReputationResult(String status, String provider, String host,
                                  String checkedAt, String observedAt, Long cacheAgeSeconds, String detail) {
    public static UrlReputationResult disabled(String host) {
        return new UrlReputationResult("DISABLED", "none", host, Instant.now().toString(), null, null,
                "Optional URL reputation lookup is disabled.");
    }
}
