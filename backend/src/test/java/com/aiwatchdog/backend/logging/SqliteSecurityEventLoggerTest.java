package com.aiwatchdog.backend.logging;

import org.junit.jupiter.api.Test;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;

class SqliteSecurityEventLoggerTest {

    private static final String DB_URL = "jdbc:sqlite:aiwatchdog.db";

    @Test
    void loggerPersistsSecurityEvent() throws Exception {
        SqliteSecurityEventLogger logger =
                new SqliteSecurityEventLogger();

        SecurityEvent event = new SecurityEvent(
                null,
                Instant.now(),
                "https://example.com",
                0.011523,
                1,
                "SAFE",
                "BENIGN",
                "ALLOW"
        );

        logger.log(event);

        try (Connection connection = DriverManager.getConnection(DB_URL);
             Statement statement = connection.createStatement();
             ResultSet result = statement.executeQuery(
                     "SELECT * FROM security_events ORDER BY id DESC LIMIT 1")) {

            assertTrue(result.next());

            assertNotNull(result.getObject("id"));
            assertNotNull(result.getString("timestamp"));
            assertEquals("https://example.com", result.getString("url"));
            assertEquals(0.011523, result.getDouble("phishing_probability"));
            assertEquals(1, result.getInt("risk_score"));
            assertEquals("SAFE", result.getString("risk_level"));
            assertEquals("BENIGN", result.getString("prediction"));
            assertEquals("ALLOW", result.getString("decision"));
        }
    }

    @Test
    void nullEventIsRejected() {
        SqliteSecurityEventLogger logger =
                new SqliteSecurityEventLogger();

        assertThrows(
                IllegalArgumentException.class,
                () -> logger.log(null)
        );
    }

    @Test
    void invalidRiskScoreIsRejected() {
        SqliteSecurityEventLogger logger =
                new SqliteSecurityEventLogger();

        SecurityEvent event = new SecurityEvent(
                null,
                Instant.now(),
                "https://example.com",
                0.5,
                101,
                "HIGH RISK",
                "PHISHING",
                "BLOCK"
        );

        assertThrows(
                IllegalArgumentException.class,
                () -> logger.log(event)
        );
    }

    @Test
    void invalidProbabilityIsRejected() {
        SqliteSecurityEventLogger logger =
                new SqliteSecurityEventLogger();

        SecurityEvent event = new SecurityEvent(
                null,
                Instant.now(),
                "https://example.com",
                1.5,
                50,
                "SUSPICIOUS",
                "PHISHING",
                "WARN"
        );

        assertThrows(
                IllegalArgumentException.class,
                () -> logger.log(event)
        );
    }

    @Test
    void normalizesSpacedRiskAndLowercaseDecisionBeforePersistence() throws Exception {
        SqliteSecurityEventLogger logger = new SqliteSecurityEventLogger();
        String url = "https://normalization-test.invalid/" + System.nanoTime();
        logger.log(new SecurityEvent(null, Instant.now(), url, 0.99, 99,
                "HIGH RISK", " phishing ", "block"));

        try (Connection connection = DriverManager.getConnection(DB_URL);
             PreparedStatement statement = connection.prepareStatement(
                     "SELECT risk_level, prediction, decision FROM security_events WHERE url = ?")) {
            statement.setString(1, url);
            try (ResultSet result = statement.executeQuery()) {
                assertTrue(result.next());
                assertEquals("HIGH_RISK", result.getString("risk_level"));
                assertEquals("PHISHING", result.getString("prediction"));
                assertEquals("BLOCK", result.getString("decision"));
            }
        }
    }
}
