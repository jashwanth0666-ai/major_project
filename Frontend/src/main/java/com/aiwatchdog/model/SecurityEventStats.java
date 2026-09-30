package com.aiwatchdog.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public record SecurityEventStats(long totalEvents, long safeCount, long lowRiskCount,
                                 long suspiciousCount, long highRiskCount, long allowCount,
                                 long reviewCount, long warnCount, long blockCount,
                                 long phishingCount, long benignCount) { }
