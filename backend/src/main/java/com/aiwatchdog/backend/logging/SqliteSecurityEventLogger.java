package com.aiwatchdog.backend.logging;

import com.aiwatchdog.backend.policy.Decision;
import com.aiwatchdog.backend.policy.RiskLevel;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

@Service
public class SqliteSecurityEventLogger implements SecurityEventLogger {

    private final String dbUrl;

    public SqliteSecurityEventLogger() {
        this("aiwatchdog.db");
    }

    @Autowired
    public SqliteSecurityEventLogger(
            @Value("${ai-watchdog.security.db-path:aiwatchdog.db}") String dbPath) {
        this.dbUrl = "jdbc:sqlite:" + dbPath;
        initializeDatabase();
    }

    private void initializeDatabase() {
        String sql = """
                CREATE TABLE IF NOT EXISTS security_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    url TEXT NOT NULL,
                    phishing_probability REAL NOT NULL,
                    risk_score INTEGER NOT NULL,
                    risk_level TEXT NOT NULL,
                    prediction TEXT NOT NULL,
                    decision TEXT NOT NULL
                )
                """;

        try (Connection connection = DriverManager.getConnection(dbUrl);
             Statement statement = connection.createStatement()) {

            statement.execute(sql);

        } catch (SQLException e) {
            throw new IllegalStateException(
                    "Failed to initialize SQLite database", e);
        }
    }

    @Override
    public void log(SecurityEvent event) {
        if (event == null) {
            throw new IllegalArgumentException("Security event must not be null");
        }

        if (event.url() == null || event.url().isBlank()) {
            throw new IllegalArgumentException("URL must not be blank");
        }

        if (event.riskScore() < 0 || event.riskScore() > 100) {
            throw new IllegalArgumentException("Risk score must be between 0 and 100");
        }

        if (event.riskLevel() == null || event.riskLevel().isBlank()) {
            throw new IllegalArgumentException("Risk level must not be blank");
        }

        if (event.prediction() == null || event.prediction().isBlank()) {
            throw new IllegalArgumentException("Prediction must not be blank");
        }

        if (event.decision() == null || event.decision().isBlank()) {
            throw new IllegalArgumentException("Decision must not be blank");
        }

        if (event.phishingProbability() < 0.0
                || event.phishingProbability() > 1.0) {
            throw new IllegalArgumentException(
                    "Phishing probability must be between 0.0 and 1.0");
        }

        String normalizedRiskLevel = RiskLevel.parse(event.riskLevel()).name();
        String normalizedDecision = parseDecision(event.decision()).name();
        String normalizedPrediction = event.prediction().trim().toUpperCase(java.util.Locale.ROOT);
        if (!normalizedPrediction.equals("BENIGN") && !normalizedPrediction.equals("PHISHING")) {
            throw new IllegalArgumentException("Prediction must be BENIGN or PHISHING");
        }

        String sql = """
                INSERT INTO security_events
                (timestamp, url, phishing_probability, risk_score,
                 risk_level, prediction, decision)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """;

        Instant timestamp = event.timestamp() != null
                ? event.timestamp()
                : Instant.now();

        try (Connection connection = DriverManager.getConnection(dbUrl);
             PreparedStatement statement = connection.prepareStatement(sql)) {

            statement.setString(1, timestamp.toString());
            statement.setString(2, event.url());
            statement.setDouble(3, event.phishingProbability());
            statement.setInt(4, event.riskScore());
            statement.setString(5, normalizedRiskLevel);
            statement.setString(6, normalizedPrediction);
            statement.setString(7, normalizedDecision);

            statement.executeUpdate();

        } catch (SQLException e) {
            throw new IllegalStateException(
                    "Failed to persist security event", e);
        }
    }

    private Decision parseDecision(String value) {
        try {
            return Decision.valueOf(value.trim().toUpperCase(java.util.Locale.ROOT));
        } catch (IllegalArgumentException exception) {
            throw new IllegalArgumentException("Unsupported decision: " + value, exception);
        }
    }
}
