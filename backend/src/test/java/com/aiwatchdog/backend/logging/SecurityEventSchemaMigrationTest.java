package com.aiwatchdog.backend.logging;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Path;
import java.sql.*;
import java.time.Instant;
import static org.junit.jupiter.api.Assertions.*;

class SecurityEventSchemaMigrationTest {
    @TempDir Path temp;

    @Test void migratesLegacyUrlRowsAndAppendsFileAssessmentToSameHistory() throws Exception {
        Path db = temp.resolve("events.db");
        try (Connection c = DriverManager.getConnection("jdbc:sqlite:" + db);
             Statement s = c.createStatement()) {
            s.execute("CREATE TABLE security_events (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL,"
                    + " url TEXT NOT NULL, phishing_probability REAL NOT NULL, risk_score INTEGER NOT NULL,"
                    + " risk_level TEXT NOT NULL, prediction TEXT NOT NULL, decision TEXT NOT NULL)");
            s.execute("INSERT INTO security_events(timestamp,url,phishing_probability,risk_score,risk_level,prediction,decision)"
                    + " VALUES ('2026-01-01T00:00:00Z','https://old.test',0.1,10,'SAFE','BENIGN','ALLOW')");
        }
        SqliteSecurityEventLogger logger = new SqliteSecurityEventLogger(db.toString());
        logger.logAssessment(new SecurityEvent(null, Instant.now(), null, null, null, null, null, "REVIEW",
                "THREAT_ASSESSMENT", "FILE", "a".repeat(64), "corr-1", "{\"status\":\"PARTIAL\"}"));
        try (Connection c = DriverManager.getConnection("jdbc:sqlite:" + db);
             Statement s = c.createStatement(); ResultSet r = s.executeQuery("SELECT COUNT(*) FROM security_events")) {
            assertTrue(r.next()); assertEquals(2, r.getInt(1));
        }
        try (Connection c = DriverManager.getConnection("jdbc:sqlite:" + db);
             PreparedStatement p = c.prepareStatement("SELECT url, risk_level, event_type, subject_id, details_json FROM security_events WHERE id=2");
             ResultSet r = p.executeQuery()) {
            assertTrue(r.next()); assertNull(r.getString("url")); assertNull(r.getString("risk_level"));
            assertEquals("THREAT_ASSESSMENT", r.getString("event_type"));
            assertEquals("a".repeat(64), r.getString("subject_id"));
            assertEquals("{\"status\":\"PARTIAL\"}", r.getString("details_json"));
        }
        var auditRows = new SqliteSecurityEventRepository(db.toString()).findRecentAssessments(10);
        assertEquals(1, auditRows.size());
        assertEquals("THREAT_ASSESSMENT", auditRows.get(0).eventType());
    }
}
