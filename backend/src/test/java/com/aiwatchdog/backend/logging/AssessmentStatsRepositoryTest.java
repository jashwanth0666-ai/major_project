package com.aiwatchdog.backend.logging;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;

class AssessmentStatsRepositoryTest {
    @TempDir Path temp;

    @Test
    void aggregatesRealPersistedAssessmentFieldsAndReputationSources() {
        String db = temp.resolve("assessments.db").toString();
        SqliteSecurityEventLogger logger = new SqliteSecurityEventLogger(db);
        logger.logAssessment(new SecurityEvent(null, Instant.parse("2026-10-01T00:00:00Z"), null,
                null, null, null, null, "ALLOW", "THREAT_ASSESSMENT", "URL", "https://example.test/",
                "corr-url", "{\"status\":\"COMPLETE\",\"sources\":{\"urlModel\":{}}}"));
        logger.logAssessment(new SecurityEvent(null, Instant.parse("2026-10-02T00:00:00Z"), null,
                null, null, null, null, "REVIEW", "THREAT_ASSESSMENT", "FILE", "abc123",
                "corr-file", "{\"status\":\"PARTIAL\",\"sources\":{\"fileReputation\":{\"reputationStatus\":\"UNKNOWN\"}}}"));

        AssessmentStats stats = new SqliteSecurityEventRepository(db).getAssessmentStats();
        assertEquals(2, stats.totalAssessments());
        assertEquals(1, stats.urlAssessments());
        assertEquals(1, stats.fileAssessments());
        assertEquals(1, stats.allowCount());
        assertEquals(1, stats.reviewCount());
        assertEquals(1, stats.completeCount());
        assertEquals(1, stats.partialCount());
        assertEquals(1, stats.unknownReputationCount());
        assertEquals(0, stats.knownCleanCount());
    }
}
