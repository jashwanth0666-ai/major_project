package com.aiwatchdog.backend.logging;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Repository;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * SQLite-backed implementation of {@link SecurityEventRepository}.
 * All queries use PreparedStatement - no string concatenation of user data.
 * The database file path is configurable via ai-watchdog.security.db-path.
 */
@Repository
public class SqliteSecurityEventRepository implements SecurityEventRepository {

    private final String dbUrl;

    public SqliteSecurityEventRepository(
            @Value("${ai-watchdog.security.db-path:aiwatchdog.db}") String dbPath) {
        this.dbUrl = "jdbc:sqlite:" + dbPath;
        initializeSchema();
    }

    private void initializeSchema() {
        String sql = "CREATE TABLE IF NOT EXISTS security_events ("
                + "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                + "timestamp TEXT NOT NULL,"
                + "url TEXT NOT NULL,"
                + "phishing_probability REAL NOT NULL,"
                + "risk_score INTEGER NOT NULL,"
                + "risk_level TEXT NOT NULL,"
                + "prediction TEXT NOT NULL,"
                + "decision TEXT NOT NULL"
                + ")";

        try (Connection conn = connect();
             Statement stmt = conn.createStatement()) {
            stmt.execute(sql);
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to initialise security_events schema", e);
        }
    }

    @Override
    public SecurityEvent save(SecurityEvent event) {
        String sql = "INSERT INTO security_events"
                + " (timestamp, url, phishing_probability, risk_score, risk_level, prediction, decision)"
                + " VALUES (?, ?, ?, ?, ?, ?, ?)";

        Instant ts = event.timestamp() != null ? event.timestamp() : Instant.now();

        try (Connection conn = connect();
             PreparedStatement ps = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {

            ps.setString(1, ts.toString());
            ps.setString(2, event.url());
            ps.setDouble(3, event.phishingProbability());
            ps.setInt(4, event.riskScore());
            ps.setString(5, event.riskLevel());
            ps.setString(6, event.prediction());
            ps.setString(7, event.decision());
            ps.executeUpdate();

            try (ResultSet keys = ps.getGeneratedKeys()) {
                long generatedId = keys.next() ? keys.getLong(1) : -1L;
                return new SecurityEvent(
                        generatedId, ts,
                        event.url(), event.phishingProbability(),
                        event.riskScore(), event.riskLevel(),
                        event.prediction(), event.decision());
            }

        } catch (SQLException e) {
            throw new IllegalStateException("Failed to persist security event", e);
        }
    }

    @Override
    public List<SecurityEvent> findRecent(int limit) {
        String sql = "SELECT id, timestamp, url, phishing_probability,"
                + " risk_score, risk_level, prediction, decision"
                + " FROM security_events ORDER BY id DESC LIMIT ?";

        try (Connection conn = connect();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setInt(1, limit);
            return collectResults(ps);
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to retrieve recent security events", e);
        }
    }

    @Override
    public List<SecurityEvent> findByRiskLevel(String riskLevel) {
        String sql = "SELECT id, timestamp, url, phishing_probability,"
                + " risk_score, risk_level, prediction, decision"
                + " FROM security_events WHERE risk_level = ? ORDER BY id DESC";

        try (Connection conn = connect();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, riskLevel);
            return collectResults(ps);
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to retrieve events by risk level", e);
        }
    }

    @Override
    public List<SecurityEvent> findByDecision(String decision) {
        String sql = "SELECT id, timestamp, url, phishing_probability,"
                + " risk_score, risk_level, prediction, decision"
                + " FROM security_events WHERE decision = ? ORDER BY id DESC";

        try (Connection conn = connect();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, decision);
            return collectResults(ps);
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to retrieve events by decision", e);
        }
    }

    @Override
    public SecurityEventStats getStats() {
        String sql = "SELECT"
                + " COUNT(*) AS total,"
                + " SUM(CASE WHEN risk_level = 'SAFE'       THEN 1 ELSE 0 END) AS safe_cnt,"
                + " SUM(CASE WHEN risk_level = 'LOW_RISK'   THEN 1 ELSE 0 END) AS low_risk_cnt,"
                + " SUM(CASE WHEN risk_level = 'SUSPICIOUS' THEN 1 ELSE 0 END) AS suspicious_cnt,"
                + " SUM(CASE WHEN risk_level = 'HIGH_RISK'  THEN 1 ELSE 0 END) AS high_risk_cnt,"
                + " SUM(CASE WHEN decision   = 'ALLOW'      THEN 1 ELSE 0 END) AS allow_cnt,"
                + " SUM(CASE WHEN decision   = 'REVIEW'     THEN 1 ELSE 0 END) AS review_cnt,"
                + " SUM(CASE WHEN decision   = 'WARN'       THEN 1 ELSE 0 END) AS warn_cnt,"
                + " SUM(CASE WHEN decision   = 'BLOCK'      THEN 1 ELSE 0 END) AS block_cnt,"
                + " SUM(CASE WHEN prediction = 'PHISHING'   THEN 1 ELSE 0 END) AS phishing_cnt,"
                + " SUM(CASE WHEN prediction = 'BENIGN'     THEN 1 ELSE 0 END) AS benign_cnt"
                + " FROM security_events";

        try (Connection conn = connect();
             PreparedStatement ps = conn.prepareStatement(sql);
             ResultSet rs = ps.executeQuery()) {

            if (rs.next()) {
                return new SecurityEventStats(
                        rs.getLong("total"),
                        rs.getLong("safe_cnt"),
                        rs.getLong("low_risk_cnt"),
                        rs.getLong("suspicious_cnt"),
                        rs.getLong("high_risk_cnt"),
                        rs.getLong("allow_cnt"),
                        rs.getLong("review_cnt"),
                        rs.getLong("warn_cnt"),
                        rs.getLong("block_cnt"),
                        rs.getLong("phishing_cnt"),
                        rs.getLong("benign_cnt"));
            }
            return new SecurityEventStats(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);

        } catch (SQLException e) {
            throw new IllegalStateException("Failed to calculate security event statistics", e);
        }
    }

    private Connection connect() throws SQLException {
        return DriverManager.getConnection(dbUrl);
    }

    private List<SecurityEvent> collectResults(PreparedStatement ps) throws SQLException {
        List<SecurityEvent> events = new ArrayList<>();
        try (ResultSet rs = ps.executeQuery()) {
            while (rs.next()) {
                events.add(new SecurityEvent(
                        rs.getLong("id"),
                        Instant.parse(rs.getString("timestamp")),
                        rs.getString("url"),
                        rs.getDouble("phishing_probability"),
                        rs.getInt("risk_score"),
                        rs.getString("risk_level"),
                        rs.getString("prediction"),
                        rs.getString("decision")));
            }
        }
        return events;
    }
}
