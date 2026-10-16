package com.aiwatchdog.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public record AssessmentStats(long totalAssessments, long urlAssessments, long fileAssessments,
        long allowCount, long reviewCount, long warnCount, long blockCount,
        long completeCount, long partialCount, long knownMaliciousCount, long knownCleanCount,
        long unknownReputationCount, long lookupErrorCount) { }
