package com.aiwatchdog.backend.assessment;

import java.time.Instant;

/** A single local exact-host rule match; configured rule sets are never returned. */
public record DomainRuleMatch(String status, String action, String provider, String host,
                              String matchedHost, String checkedAt) {
    public static DomainRuleMatch none(String host) {
        return new DomainRuleMatch("COMPLETE", "NONE", "local-config", host, null, Instant.now().toString());
    }
}
