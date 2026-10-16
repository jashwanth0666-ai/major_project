package com.aiwatchdog.backend.logging;

/** Lifetime aggregates over persisted unified assessments in the shared security_events table. */
public record AssessmentStats(long totalAssessments, long urlAssessments, long fileAssessments,
        long allowCount, long reviewCount, long warnCount, long blockCount,
        long completeCount, long partialCount, long knownMaliciousCount, long knownCleanCount,
        long unknownReputationCount, long lookupErrorCount) { }
