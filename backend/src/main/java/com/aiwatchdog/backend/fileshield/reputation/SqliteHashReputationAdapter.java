package com.aiwatchdog.backend.fileshield.reputation;

import com.aiwatchdog.backend.fileshield.config.FileShieldProperties;
import com.aiwatchdog.backend.fileshield.model.ReputationStatus;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import org.sqlite.SQLiteConfig;
import java.util.Locale;
import java.util.regex.Pattern;
import java.util.List;
import java.time.Instant;

@Service
public class SqliteHashReputationAdapter implements HashReputationService {
    private static final Pattern SHA256 = Pattern.compile("[a-fA-F0-9]{64}");
    private static final String CREATE_SCHEMA = """
            CREATE TABLE IF NOT EXISTS hash_reputation (
              sha256 TEXT PRIMARY KEY,
              reputation TEXT NOT NULL,
              source TEXT NOT NULL,
              description TEXT,
              updated_at TEXT NOT NULL
            )
            """;
    private final FileShieldProperties properties;
    private final ConfiguredThreatIntelProvider threatIntel;

    @Autowired
    public SqliteHashReputationAdapter(FileShieldProperties properties, ConfiguredThreatIntelProvider threatIntel) {
        this.properties = properties; this.threatIntel = threatIntel;
        initializeDatabase();
    }

    public SqliteHashReputationAdapter(FileShieldProperties properties) {
        this(properties, null);
    }

    private void initializeDatabase() {
        Path database = properties.getReputationDatabasePath().toAbsolutePath().normalize();
        try {
            Path parent = database.getParent();
            if (parent != null) Files.createDirectories(parent);
            try (Connection connection = DriverManager.getConnection("jdbc:sqlite:" + database);
                 var statement = connection.createStatement()) {
                statement.execute(CREATE_SCHEMA);
            }
        } catch (SQLException | RuntimeException exception) {
            throw new IllegalStateException("Failed to initialize file reputation database", exception);
        } catch (java.io.IOException exception) {
            throw new IllegalStateException("Failed to create file reputation database directory", exception);
        }
    }

    @Override
    public HashReputation lookup(String sha256) {
        if (sha256 == null || !SHA256.matcher(sha256).matches())
            throw new IllegalArgumentException("SHA-256 must contain exactly 64 hexadecimal characters");
        var database = properties.getReputationDatabasePath().toAbsolutePath().normalize();
        HashReputation local = lookupLocal(sha256, database);
        if (local.status() == ReputationStatus.KNOWN_CLEAN || local.status() == ReputationStatus.KNOWN_MALICIOUS
                || local.status() == ReputationStatus.SUSPICIOUS) return local;
        if (threatIntel == null || !properties.isThreatIntelEnabled()) return local;
        HashReputation remote = threatIntel.lookup(sha256);
        if (remote.status() == ReputationStatus.LOOKUP_ERROR) return remote;
        if (remote.status() == ReputationStatus.UNKNOWN && local.status() == ReputationStatus.LOOKUP_ERROR) return local;
        return remote;
    }

    @Override
    public List<ReputationProviderStatus> providerStatuses() {
        initializeDatabase();
        Path database = properties.getReputationDatabasePath().toAbsolutePath().normalize();
        boolean available = false;
        String error = null;
        if (Files.isRegularFile(database)) {
            SQLiteConfig config = new SQLiteConfig(); config.setReadOnly(true);
            try (Connection connection = DriverManager.getConnection("jdbc:sqlite:" + database, config.toProperties());
                 PreparedStatement statement = connection.prepareStatement("SELECT sha256, reputation, source, description FROM hash_reputation LIMIT 0")) {
                statement.executeQuery().close(); available = true;
            } catch (SQLException | RuntimeException failure) { error = "DATABASE_UNAVAILABLE"; }
        } else error = "DATABASE_UNAVAILABLE";
        return java.util.stream.Stream.concat(
                java.util.stream.Stream.of(new ReputationProviderStatus("local-sqlite", available ? "READY" : "UNAVAILABLE", error, Instant.now())),
                threatIntel == null ? java.util.stream.Stream.empty() : java.util.stream.Stream.of(threatIntel.health()))
                .toList();
    }

    private HashReputation lookupLocal(String sha256, Path database) {
        String url = "jdbc:sqlite:" + database;
        String sql = "SELECT reputation, source, description FROM hash_reputation WHERE sha256 = ?";
        SQLiteConfig config = new SQLiteConfig();
        config.setReadOnly(true);
        try (Connection connection = DriverManager.getConnection(url, config.toProperties());
             PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, sha256.toLowerCase(Locale.ROOT));
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) return new HashReputation(ReputationStatus.UNKNOWN, "local-sqlite", "Hash is not present in the local reputation list.");
                ReputationStatus status;
                try { status = ReputationStatus.valueOf(result.getString("reputation")); }
                catch (RuntimeException invalid) { return new HashReputation(ReputationStatus.LOOKUP_ERROR, "local-sqlite", "Reputation database contains an invalid record."); }
                if (status != ReputationStatus.KNOWN_CLEAN && status != ReputationStatus.KNOWN_MALICIOUS
                        && status != ReputationStatus.SUSPICIOUS)
                    return new HashReputation(ReputationStatus.LOOKUP_ERROR, "local-sqlite", "Reputation database contains an invalid record.");
                String source = result.getString("source");
                if (source == null || source.isBlank()) return new HashReputation(ReputationStatus.LOOKUP_ERROR, "local-sqlite", "Reputation record is incomplete.");
                return new HashReputation(status, source, result.getString("description"));
            }
        } catch (SQLException | RuntimeException exception) {
            return new HashReputation(ReputationStatus.LOOKUP_ERROR, "local-sqlite", "Reputation database lookup failed.");
        }
    }
}
