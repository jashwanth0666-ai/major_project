package com.aiwatchdog.backend.assessment;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.net.IDN;
import java.time.Instant;
import java.util.Arrays;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ConcurrentSkipListSet;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.stream.Collectors;

/** Operator-managed exact-host rules loaded from process configuration at startup. */
@Component
public class ConfiguredLocalDomainRuleService {
    private final Set<String> denylist;
    private final Set<String> allowlist = new ConcurrentSkipListSet<>();
    private final String dbUrl;

    public ConfiguredLocalDomainRuleService(String denylist, String allowlist) {
        this(denylist, allowlist, java.nio.file.Path.of(System.getProperty("java.io.tmpdir"),
                "aiwatchdog-domain-rules-" + java.util.UUID.randomUUID() + ".db").toString());
    }

    @Autowired
    public ConfiguredLocalDomainRuleService(
            @Value("${ai-watchdog.url-rules.denylist:}") String denylist,
            @Value("${ai-watchdog.url-rules.allowlist:}") String allowlist,
            @Value("${ai-watchdog.security.db-path:aiwatchdog.db}") String dbPath) {
        this.dbUrl = "jdbc:sqlite:" + dbPath;
        this.denylist = parse(denylist);
        this.allowlist.addAll(parse(allowlist));
        loadPersistedAllowlist();
    }

    public DomainRuleMatch lookup(String host) {
        String normalized = normalize(host);
        if (normalized == null) return DomainRuleMatch.none(host);
        if (denylist.contains(normalized))
            return new DomainRuleMatch("COMPLETE", "DENY", "local-config", normalized, normalized, Instant.now().toString());
        if (allowlist.contains(normalized))
            return new DomainRuleMatch("COMPLETE", "ALLOWLIST_EXCEPTION", "local-config", normalized, normalized, Instant.now().toString());
        return DomainRuleMatch.none(normalized);
    }

    public synchronized Set<String> listAllowlist() { return Set.copyOf(allowlist); }

    public synchronized String addAllowlistEntry(String input) {
        String domain = normalizeInput(input);
        if (domain == null) throw new IllegalArgumentException("Enter a valid domain name, such as example.com.");
        try (Connection c = DriverManager.getConnection(dbUrl);
             PreparedStatement p = c.prepareStatement("INSERT OR IGNORE INTO url_domain_allowlist(domain) VALUES (?)")) {
            p.setString(1, domain);
            p.executeUpdate();
            allowlist.add(domain);
            return domain;
        } catch (SQLException e) { throw new IllegalStateException("Could not save the domain exception.", e); }
    }

    public synchronized void removeAllowlistEntry(String input) {
        String domain = normalizeInput(input);
        if (domain == null) throw new IllegalArgumentException("Invalid domain exception.");
        try (Connection c = DriverManager.getConnection(dbUrl);
             PreparedStatement p = c.prepareStatement("DELETE FROM url_domain_allowlist WHERE domain = ?")) {
            p.setString(1, domain);
            p.executeUpdate();
            allowlist.remove(domain);
        } catch (SQLException e) { throw new IllegalStateException("Could not remove the domain exception.", e); }
    }

    private void loadPersistedAllowlist() {
        try (Connection c = DriverManager.getConnection(dbUrl); Statement s = c.createStatement()) {
            s.execute("CREATE TABLE IF NOT EXISTS url_domain_allowlist (domain TEXT PRIMARY KEY, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)");
            try (ResultSet rs = s.executeQuery("SELECT domain FROM url_domain_allowlist ORDER BY domain")) {
                while (rs.next()) allowlist.add(rs.getString(1));
            }
        } catch (SQLException e) { throw new IllegalStateException("Could not load domain exceptions.", e); }
    }

    private String normalizeInput(String input) {
        if (input == null || input.isBlank()) return null;
        String value = input.trim();
        if (value.contains("://")) {
            try { value = java.net.URI.create(value).getHost(); } catch (IllegalArgumentException e) { return null; }
        }
        if (value == null || value.contains("/") || value.contains("*") || value.contains(":")) return null;
        return normalize(value);
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
