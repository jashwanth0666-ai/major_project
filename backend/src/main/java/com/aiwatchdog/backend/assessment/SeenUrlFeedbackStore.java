package com.aiwatchdog.backend.assessment;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

/** Stores only a hash for exact URLs that a user explicitly marked as false positives. */
@Service
public class SeenUrlFeedbackStore {
    private static final String NOOP = "noop:";
    private final String dbUrl;

    public SeenUrlFeedbackStore(@Value("${ai-watchdog.security.db-path:aiwatchdog.db}") String dbPath) {
        this.dbUrl = "jdbc:sqlite:" + dbPath;
        initialize();
    }

    private SeenUrlFeedbackStore() { this.dbUrl = NOOP; }

    static SeenUrlFeedbackStore noop() { return new SeenUrlFeedbackStore(); }

    private void initialize() {
        try (Connection connection = connect(); Statement statement = connection.createStatement()) {
            statement.execute("CREATE TABLE IF NOT EXISTS seen_url_assessments (assessment_id TEXT PRIMARY KEY, correlation_id TEXT NOT NULL DEFAULT '', url_hash TEXT NOT NULL, model_prediction TEXT NOT NULL DEFAULT '')");
            boolean hasPrediction = false;
            boolean hasCorrelation = false;
            try (Statement columnStatement = connection.createStatement();
                 ResultSet columns = columnStatement.executeQuery("PRAGMA table_info(seen_url_assessments)")) {
                while (columns.next()) {
                    String name = columns.getString("name");
                    if ("model_prediction".equalsIgnoreCase(name)) hasPrediction = true;
                    if ("correlation_id".equalsIgnoreCase(name)) hasCorrelation = true;
                }
            }
            if (!hasCorrelation) statement.execute("ALTER TABLE seen_url_assessments ADD COLUMN correlation_id TEXT NOT NULL DEFAULT ''");
            if (!hasPrediction) statement.execute("ALTER TABLE seen_url_assessments ADD COLUMN model_prediction TEXT NOT NULL DEFAULT ''");
            statement.execute("CREATE INDEX IF NOT EXISTS idx_seen_url_assessments_hash ON seen_url_assessments(url_hash)");
            statement.execute("CREATE TABLE IF NOT EXISTS seen_url (url_hash TEXT PRIMARY KEY, assessment_id TEXT NOT NULL, marked_at TEXT NOT NULL, expires_at TEXT NOT NULL)");
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to initialize exact URL feedback storage", e);
        }
    }

    public void recordAssessment(String assessmentId, String correlationId, String urlHash, String modelPrediction) {
        if (isNoop() || assessmentId == null || urlHash == null) return;
        try (Connection connection = connect(); PreparedStatement statement = connection.prepareStatement(
                "INSERT OR REPLACE INTO seen_url_assessments(assessment_id,correlation_id,url_hash,model_prediction) VALUES (?,?,?,?)")) {
            statement.setString(1, assessmentId);
            statement.setString(2, correlationId == null ? "" : correlationId);
            statement.setString(3, urlHash);
            statement.setString(4, modelPrediction == null ? "" : modelPrediction);
            statement.executeUpdate();
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to associate URL assessment with feedback key", e);
        }
    }

    /** Returns false if the assessment does not belong to a persisted URL assessment. */
    public boolean markSafe(String assessmentId, String correlationId) {
        if (isNoop() || assessmentId == null || correlationId == null) return false;
        Instant marked = Instant.now();
        String sql = "INSERT INTO seen_url(url_hash,assessment_id,marked_at,expires_at) "
                + "SELECT url_hash,assessment_id,?,? FROM seen_url_assessments WHERE assessment_id=? AND correlation_id=? AND upper(model_prediction)='PHISHING' "
                + "ON CONFLICT(url_hash) DO UPDATE SET assessment_id=excluded.assessment_id, "
                + "marked_at=excluded.marked_at, expires_at=excluded.expires_at";
        try (Connection connection = connect(); PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, marked.toString());
            statement.setString(2, marked.plus(30, ChronoUnit.DAYS).toString());
            statement.setString(3, assessmentId);
            statement.setString(4, correlationId);
            return statement.executeUpdate() > 0;
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to store exact URL false-positive feedback", e);
        }
    }

    public SeenUrl findCurrentSafe(String urlHash) {
        if (isNoop() || urlHash == null) return null;
        try (Connection connection = connect(); PreparedStatement statement = connection.prepareStatement(
                "SELECT assessment_id,marked_at,expires_at FROM seen_url WHERE url_hash=? AND expires_at>?")) {
            statement.setString(1, urlHash);
            statement.setString(2, Instant.now().toString());
            try (ResultSet result = statement.executeQuery()) {
                return result.next() ? new SeenUrl(result.getString(1), result.getString(2), result.getString(3)) : null;
            }
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to look up exact URL feedback", e);
        }
    }

    private Connection connect() throws SQLException { return DriverManager.getConnection(dbUrl); }
    private boolean isNoop() { return dbUrl.startsWith(NOOP); }

    public record SeenUrl(String assessmentId, String markedAt, String expiresAt) { }
}
