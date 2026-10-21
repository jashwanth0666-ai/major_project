package com.aiwatchdog.backend.logging;

import java.util.List;
import java.util.Optional;

/**
 * Repository interface for persisting and retrieving {@link SecurityEvent} records.
 * Implementations must use parameterized SQL to prevent injection.
 */
public interface SecurityEventRepository {

    /**
     * Persists a validated event and returns the stored instance with generated id.
     */
    SecurityEvent save(SecurityEvent event);

    /**
     * Returns up to {@code limit} most-recent events, newest first.
     */
    List<SecurityEvent> findRecent(int limit);

    /** Returns structured threat-assessment audit events, newest first. */
    List<SecurityEvent> findRecentAssessments(int limit);

    /** Looks up one persisted unified assessment by its public assessment ID. */
    Optional<SecurityEvent> findAssessmentById(String assessmentId);

    /** Human labels linked to URL assessments, newest first. */
    default List<SecurityEvent> findRecentFeedback(int limit) { return List.of(); }

    List<SecurityEvent> findRecentFileOperations(int limit);
    List<SecurityEvent> findActiveQuarantines();
    List<SecurityEvent> findIncompleteFileOperations();
    Optional<SecurityEvent> findLatestFileOperation(String operationId);

    /** Aggregate counts for persisted unified assessments, without loading event rows. */
    AssessmentStats getAssessmentStats();

    /** Full-period aggregate-only phishing insights, with feedback linked to its URL assessment. */
    InsightPeriodMetrics getInsightPeriodMetrics(java.time.Instant startInclusive, java.time.Instant endExclusive);

    /**
     * Returns all events matching the given risk level (SAFE/LOW_RISK/SUSPICIOUS/HIGH_RISK), newest first.
     */
    List<SecurityEvent> findByRiskLevel(String riskLevel);

    /**
     * Returns all events matching the given decision (ALLOW/REVIEW/WARN/BLOCK), newest first.
     */
    List<SecurityEvent> findByDecision(String decision);

    /**
     * Returns aggregate counts computed via SQL aggregation.
     */
    SecurityEventStats getStats();
}
