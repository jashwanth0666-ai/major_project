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
import java.util.Optional;
import java.util.LinkedHashMap;
import java.util.Map;

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
        try (Connection conn = connect();
             Statement stmt = conn.createStatement()) {
            SecurityEventSchema.initialize(conn);
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
                + " , event_type, subject_type, subject_id, correlation_id, details_json"
                + " FROM security_events WHERE event_type = 'URL_ANALYSIS' ORDER BY id DESC LIMIT ?";

        try (Connection conn = connect();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setInt(1, limit);
            return collectResults(ps);
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to retrieve recent security events", e);
        }
    }

    @Override
    public List<SecurityEvent> findRecentAssessments(int limit) {
        String sql = "SELECT id, timestamp, url, phishing_probability, risk_score, risk_level, prediction, decision,"
                + " event_type, subject_type, subject_id, correlation_id, details_json FROM security_events"
                + " WHERE event_type = 'THREAT_ASSESSMENT' ORDER BY id DESC LIMIT ?";
        try (Connection conn = connect(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setInt(1, limit);
            return collectResults(ps);
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to retrieve recent threat assessments", e);
        }
    }

    @Override
    public Optional<SecurityEvent> findAssessmentById(String assessmentId) {
        String sql = "SELECT id, timestamp, url, phishing_probability, risk_score, risk_level, prediction, decision,"
                + " event_type, subject_type, subject_id, correlation_id, details_json FROM security_events"
                + " WHERE event_type='THREAT_ASSESSMENT'"
                + " AND json_extract(details_json, '$.assessmentId')=? LIMIT 1";
        try (Connection conn = connect(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, assessmentId);
            return collectResults(ps).stream().findFirst();
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to retrieve threat assessment", e);
        }
    }

    @Override
    public List<SecurityEvent> findRecentFeedback(int limit) {
        String sql = "SELECT id,timestamp,url,phishing_probability,risk_score,risk_level,prediction,decision,"
                + "event_type,subject_type,subject_id,correlation_id,details_json FROM security_events "
                + "WHERE event_type='URL_FEEDBACK' ORDER BY id DESC LIMIT ?";
        try (Connection conn = connect(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setInt(1, Math.max(1, Math.min(limit, 500)));
            return collectResults(ps);
        } catch (SQLException e) { throw new IllegalStateException("Failed to retrieve URL feedback", e); }
    }

    @Override
    public List<SecurityEvent> findRecentFileOperations(int limit) {
        String sql = "SELECT id,timestamp,url,phishing_probability,risk_score,risk_level,prediction,decision,event_type,"
                + "subject_type,subject_id,correlation_id,details_json FROM security_events "
                + "WHERE event_type='FILE_SHIELD_OPERATION' ORDER BY id DESC LIMIT ?";
        try (Connection conn = connect(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setInt(1, Math.max(1, Math.min(limit, 500)));
            return collectResults(ps);
        } catch (SQLException e) { throw new IllegalStateException("Failed to retrieve file-shield operation history", e); }
    }

    @Override
    public List<SecurityEvent> findActiveQuarantines() {
        String sql = "SELECT e.id,e.timestamp,e.url,e.phishing_probability,e.risk_score,e.risk_level,e.prediction,e.decision,"
                + "e.event_type,e.subject_type,e.subject_id,e.correlation_id,e.details_json FROM security_events e "
                + "JOIN (SELECT correlation_id,MAX(id) AS latest_id FROM security_events "
                + "WHERE event_type='FILE_SHIELD_OPERATION' GROUP BY correlation_id) latest ON latest.latest_id=e.id "
                + "WHERE json_extract(e.details_json,'$.state') IN ('QUARANTINED','RESTORE_FAILED','RECOVERY_REQUIRED') ORDER BY e.id DESC";
        try (Connection conn = connect(); PreparedStatement ps = conn.prepareStatement(sql)) { return collectResults(ps); }
        catch (SQLException e) { throw new IllegalStateException("Failed to retrieve active quarantines", e); }
    }

    @Override
    public List<SecurityEvent> findIncompleteFileOperations() {
        String sql = "SELECT e.id,e.timestamp,e.url,e.phishing_probability,e.risk_score,e.risk_level,e.prediction,e.decision,"
                + "e.event_type,e.subject_type,e.subject_id,e.correlation_id,e.details_json FROM security_events e "
                + "JOIN (SELECT correlation_id,MAX(id) AS latest_id FROM security_events "
                + "WHERE event_type='FILE_SHIELD_OPERATION' GROUP BY correlation_id) latest ON latest.latest_id=e.id "
                + "WHERE json_extract(e.details_json,'$.state') IN ('QUARANTINE_STARTED','RESTORE_STARTED') ORDER BY e.id";
        try (Connection conn = connect(); PreparedStatement ps = conn.prepareStatement(sql)) { return collectResults(ps); }
        catch (SQLException e) { throw new IllegalStateException("Failed to retrieve incomplete file-shield operations", e); }
    }

    @Override
    public Optional<SecurityEvent> findLatestFileOperation(String operationId) {
        String sql = "SELECT id,timestamp,url,phishing_probability,risk_score,risk_level,prediction,decision,event_type,"
                + "subject_type,subject_id,correlation_id,details_json FROM security_events "
                + "WHERE event_type='FILE_SHIELD_OPERATION' AND correlation_id=? ORDER BY id DESC LIMIT 1";
        try (Connection conn = connect(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, operationId);
            return collectResults(ps).stream().findFirst();
        } catch (SQLException e) { throw new IllegalStateException("Failed to retrieve file-shield operation", e); }
    }

    @Override
    public AssessmentStats getAssessmentStats() {
        String sql = "SELECT COUNT(*) total,"
                + " SUM(CASE WHEN subject_type='URL' THEN 1 ELSE 0 END) urls,"
                + " SUM(CASE WHEN subject_type='FILE' THEN 1 ELSE 0 END) files,"
                + " SUM(CASE WHEN decision='ALLOW' THEN 1 ELSE 0 END) allows,"
                + " SUM(CASE WHEN decision='REVIEW' THEN 1 ELSE 0 END) reviews,"
                + " SUM(CASE WHEN decision='WARN' THEN 1 ELSE 0 END) warns,"
                + " SUM(CASE WHEN decision='BLOCK' THEN 1 ELSE 0 END) blocks,"
                + " SUM(CASE WHEN json_extract(details_json,'$.status')='COMPLETE' THEN 1 ELSE 0 END) complete_cnt,"
                + " SUM(CASE WHEN json_extract(details_json,'$.status')='PARTIAL' THEN 1 ELSE 0 END) partial_cnt,"
                + " SUM(CASE WHEN json_extract(details_json,'$.sources.fileReputation.reputationStatus')='KNOWN_MALICIOUS' THEN 1 ELSE 0 END) malicious_cnt,"
                + " SUM(CASE WHEN json_extract(details_json,'$.sources.fileReputation.reputationStatus')='KNOWN_CLEAN' THEN 1 ELSE 0 END) clean_cnt,"
                + " SUM(CASE WHEN json_extract(details_json,'$.sources.fileReputation.reputationStatus')='UNKNOWN' THEN 1 ELSE 0 END) unknown_cnt,"
                + " SUM(CASE WHEN json_extract(details_json,'$.sources.fileReputation.reputationStatus')='LOOKUP_ERROR' THEN 1 ELSE 0 END) lookup_error_cnt"
                + " FROM security_events WHERE event_type='THREAT_ASSESSMENT'";
        try (Connection conn = connect(); PreparedStatement ps = conn.prepareStatement(sql); ResultSet rs = ps.executeQuery()) {
            if (!rs.next()) return new AssessmentStats(0,0,0,0,0,0,0,0,0,0,0,0,0);
            return new AssessmentStats(rs.getLong("total"), rs.getLong("urls"), rs.getLong("files"),
                    rs.getLong("allows"), rs.getLong("reviews"), rs.getLong("warns"), rs.getLong("blocks"),
                    rs.getLong("complete_cnt"), rs.getLong("partial_cnt"), rs.getLong("malicious_cnt"),
                    rs.getLong("clean_cnt"), rs.getLong("unknown_cnt"), rs.getLong("lookup_error_cnt"));
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to calculate threat assessment statistics", e);
        }
    }

    @Override
    public InsightPeriodMetrics getInsightPeriodMetrics(Instant startInclusive, Instant endExclusive) {
        String start = startInclusive.toString();
        String end = endExclusive.toString();
        String aggregateSql = "SELECT COUNT(*) AS total,"
                + " SUM(CASE WHEN json_extract(details_json,'$.sources.urlModel.prediction')='PHISHING' THEN 1 ELSE 0 END) AS phishing,"
                + " SUM(CASE WHEN json_extract(details_json,'$.sources.urlModel.risk_level')='HIGH_RISK' THEN 1 ELSE 0 END) AS high_risk,"
                + " SUM(CASE WHEN json_extract(details_json,'$.sources.urlModel.risk_level')='SUSPICIOUS' THEN 1 ELSE 0 END) AS suspicious,"
                + " SUM(CASE WHEN decision='BLOCK' THEN 1 ELSE 0 END) AS blocked,"
                + " SUM(CASE WHEN decision='REVIEW' THEN 1 ELSE 0 END) AS review,"
                + " AVG(CAST(json_extract(details_json,'$.sources.urlModel.phishing_probability') AS REAL)) AS mean_score"
                + " FROM security_events WHERE event_type='THREAT_ASSESSMENT' AND subject_type='URL' AND julianday(timestamp)>=julianday(?) AND julianday(timestamp)<julianday(?)";
        long total, phishing, highRisk, suspicious, blocked, review;
        Double mean;
        try (Connection conn = connect(); PreparedStatement ps = conn.prepareStatement(aggregateSql)) {
            ps.setString(1, start); ps.setString(2, end);
            try (ResultSet rs = ps.executeQuery()) {
                rs.next(); total = rs.getLong("total"); phishing = rs.getLong("phishing");
                highRisk = rs.getLong("high_risk"); suspicious = rs.getLong("suspicious");
                blocked = rs.getLong("blocked"); review = rs.getLong("review");
                double score = rs.getDouble("mean_score"); mean = rs.wasNull() ? null : score;
            }
        } catch (SQLException e) { throw new IllegalStateException("Failed to aggregate URL insight metrics", e); }

        Map<String, Long> signals = new LinkedHashMap<>();
        String signalSql = "SELECT json_extract(signal.value,'$.code') AS code,COUNT(*) AS count"
                + " FROM security_events e,json_each(e.details_json,'$.sources.urlHostSignals.signals') signal"
                + " WHERE e.event_type='THREAT_ASSESSMENT' AND e.subject_type='URL' AND julianday(e.timestamp)>=julianday(?) AND julianday(e.timestamp)<julianday(?)"
                + " GROUP BY code ORDER BY count DESC LIMIT 8";
        try (Connection conn = connect(); PreparedStatement ps = conn.prepareStatement(signalSql)) {
            ps.setString(1, start); ps.setString(2, end);
            try (ResultSet rs = ps.executeQuery()) { while (rs.next()) signals.put(rs.getString("code"), rs.getLong("count")); }
        } catch (SQLException e) { throw new IllegalStateException("Failed to aggregate URL host signals", e); }

        long feedbackCount = 0, falsePositives = 0, falseNegatives = 0, correct = 0;
        List<String> feedbackAssessmentIds = new ArrayList<>();
        String feedbackSql = "SELECT json_extract(f.details_json,'$.label') AS label,"
                + " json_extract(a.details_json,'$.assessmentId') AS assessment_id"
                + " FROM security_events f JOIN security_events a"
                + " ON json_extract(a.details_json,'$.assessmentId')=f.subject_id"
                + " WHERE f.event_type='URL_FEEDBACK' AND a.event_type='THREAT_ASSESSMENT' AND a.subject_type='URL'"
                + " AND julianday(f.timestamp)>=julianday(?) AND julianday(f.timestamp)<julianday(?)"
                + " AND julianday(a.timestamp)>=julianday(?) AND julianday(a.timestamp)<julianday(?) ORDER BY f.id DESC";
        try (Connection conn = connect(); PreparedStatement ps = conn.prepareStatement(feedbackSql)) {
            ps.setString(1, start); ps.setString(2, end); ps.setString(3, start); ps.setString(4, end);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    feedbackCount++;
                    String label = rs.getString("label");
                    boolean needsReview = "FALSE_POSITIVE".equals(label) || "FALSE_NEGATIVE".equals(label);
                    if ("FALSE_POSITIVE".equals(label)) falsePositives++;
                    else if ("FALSE_NEGATIVE".equals(label)) falseNegatives++;
                    else if ("CORRECT".equals(label)) correct++;
                    if (needsReview && feedbackAssessmentIds.size() < 5) feedbackAssessmentIds.add(rs.getString("assessment_id"));
                }
            }
        } catch (SQLException e) { throw new IllegalStateException("Failed to link feedback with URL assessments", e); }
        return new InsightPeriodMetrics(total, phishing, highRisk, suspicious, blocked, review, mean,
                feedbackCount, falsePositives, falseNegatives, correct, signals, feedbackAssessmentIds);
    }

    @Override
    public List<SecurityEvent> findByRiskLevel(String riskLevel) {
        String sql = "SELECT id, timestamp, url, phishing_probability,"
                + " risk_score, risk_level, prediction, decision, event_type, subject_type, subject_id, correlation_id, details_json"
                + " FROM security_events WHERE event_type = 'URL_ANALYSIS' AND risk_level = ? ORDER BY id DESC";

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
                + " risk_score, risk_level, prediction, decision, event_type, subject_type, subject_id, correlation_id, details_json"
                + " FROM security_events WHERE event_type = 'URL_ANALYSIS' AND decision = ? ORDER BY id DESC";

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
                + " FROM security_events WHERE event_type = 'URL_ANALYSIS'";

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
                        (Double) rs.getObject("phishing_probability"),
                        (Integer) rs.getObject("risk_score"),
                        rs.getString("risk_level"),
                        rs.getString("prediction"),
                        rs.getString("decision"), rs.getString("event_type"),
                        rs.getString("subject_type"), rs.getString("subject_id"),
                        rs.getString("correlation_id"), rs.getString("details_json")));
            }
        }
        return events;
    }
}
