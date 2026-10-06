package com.aiwatchdog.backend.logging;

import java.util.List;

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
