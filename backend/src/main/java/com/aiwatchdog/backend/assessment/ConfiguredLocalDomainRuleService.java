package com.aiwatchdog.backend.assessment;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.net.IDN;
import java.time.Instant;
import java.util.Arrays;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

/** Operator-managed exact-host rules loaded from process configuration at startup. */
@Component
public class ConfiguredLocalDomainRuleService {
    private final Set<String> denylist;
    private final Set<String> allowlist;

    public ConfiguredLocalDomainRuleService(
            @Value("${ai-watchdog.url-rules.denylist:}") String denylist,
            @Value("${ai-watchdog.url-rules.allowlist:}") String allowlist) {
        this.denylist = parse(denylist);
        this.allowlist = parse(allowlist);
    }

    public DomainRuleMatch lookup(String host) {
        String normalized = normalize(host);
        if (normalized == null) return DomainRuleMatch.none(host);
        if (denylist.contains(normalized))
            return new DomainRuleMatch("COMPLETE", "DENY", "local-config", normalized, normalized, Instant.now().toString());
        if (allowlist.contains(normalized))
            return new DomainRuleMatch("COMPLETE", "ALLOWLIST_EVIDENCE", "local-config", normalized, normalized, Instant.now().toString());
        return DomainRuleMatch.none(normalized);
    }

    private Set<String> parse(String configured) {
        if (configured == null || configured.isBlank()) return Set.of();
        return Arrays.stream(configured.split("[,;\\r\\n]+"))
                .map(String::trim).filter(value -> !value.isEmpty())
                .map(this::normalize).filter(value -> value != null)
                .collect(Collectors.toUnmodifiableSet());
    }

    private String normalize(String host) {
        if (host == null || host.isBlank() || host.contains("*") || host.contains("/") || host.contains(":")) return null;
        String value = host.trim().toLowerCase(Locale.ROOT);
        if (value.endsWith(".")) value = value.substring(0, value.length() - 1);
        try {
            String ascii = IDN.toASCII(value, IDN.USE_STD3_ASCII_RULES);
            return ascii.isBlank() || ascii.length() > 253 ? null : ascii;
        } catch (IllegalArgumentException invalid) { return null; }
    }
}
