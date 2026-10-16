package com.aiwatchdog.backend.logging;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashSet;
import java.util.Set;

/** Versioned, data-preserving SQLite migration for unified events. */
final class SecurityEventSchema {
    private SecurityEventSchema() { }

    static synchronized void initialize(Connection connection) throws SQLException {
        try (Statement s = connection.createStatement()) {
            s.execute("CREATE TABLE IF NOT EXISTS security_events (id INTEGER PRIMARY KEY AUTOINCREMENT,"
                    + " timestamp TEXT NOT NULL, url TEXT, phishing_probability REAL, risk_score INTEGER,"
                    + " risk_level TEXT, prediction TEXT, decision TEXT, event_type TEXT NOT NULL DEFAULT 'URL_ANALYSIS',"
                    + " subject_type TEXT, subject_id TEXT, correlation_id TEXT, details_json TEXT)");
        }
        Set<String> columns = new HashSet<>();
        try (Statement s = connection.createStatement(); ResultSet rs = s.executeQuery("PRAGMA table_info(security_events)")) {
            while (rs.next()) columns.add(rs.getString("name"));
        }
        if (columns.contains("details_json")) {
            try (Statement s = connection.createStatement()) {
                s.execute("CREATE TABLE IF NOT EXISTS security_schema_version (version INTEGER NOT NULL)");
                s.execute("INSERT INTO security_schema_version(version) SELECT 2 WHERE NOT EXISTS (SELECT 1 FROM security_schema_version)");
            }
            return;
        }
        // Old URL-only schema has NOT NULL legacy fields. Rebuild transactionally so file events can
        // leave URL/model values NULL. Existing IDs and all original values are copied unchanged.
        boolean autoCommit = connection.getAutoCommit();
        connection.setAutoCommit(false);
        try (Statement s = connection.createStatement()) {
            org.slf4j.LoggerFactory.getLogger(SecurityEventSchema.class)
                    .info("Applying data-preserving security_events schema v2 migration");
            s.execute("CREATE TABLE security_events_v2 (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL,"
                    + " url TEXT, phishing_probability REAL, risk_score INTEGER, risk_level TEXT, prediction TEXT,"
                    + " decision TEXT, event_type TEXT NOT NULL DEFAULT 'URL_ANALYSIS', subject_type TEXT,"
                    + " subject_id TEXT, correlation_id TEXT, details_json TEXT)");
            s.execute("INSERT INTO security_events_v2 (id,timestamp,url,phishing_probability,risk_score,risk_level,prediction,decision)"
                    + " SELECT id,timestamp,url,phishing_probability,risk_score,risk_level,prediction,decision FROM security_events");
            s.execute("DROP TABLE security_events");
            s.execute("ALTER TABLE security_events_v2 RENAME TO security_events");
            s.execute("CREATE TABLE IF NOT EXISTS security_schema_version (version INTEGER NOT NULL)");
            s.execute("DELETE FROM security_schema_version");
            s.execute("INSERT INTO security_schema_version(version) VALUES (2)");
            connection.commit();
        } catch (SQLException failure) {
            connection.rollback();
            throw failure;
        } finally { connection.setAutoCommit(autoCommit); }
    }
}
