package com.aiwatchdog.backend.logging;

/**
 * Lightweight V1 statistics snapshot for the security-events database.
 * Computed via SQL aggregation on demand; never cached between requests.
 */
public record SecurityEventStats(
        long totalEvents,
        long safeCount,
        long lowRiskCount,
        long suspiciousCount,
        long highRiskCount,
        long allowCount,
        long reviewCount,
        long warnCount,
        long blockCount,
        long phishingCount,
        long benignCount
) {
}
