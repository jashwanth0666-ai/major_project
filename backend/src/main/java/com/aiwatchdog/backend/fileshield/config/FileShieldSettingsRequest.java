package com.aiwatchdog.backend.fileshield.config;

import java.util.List;

/** User-configurable File Shield runtime settings. */
public record FileShieldSettingsRequest(
        boolean enabled,
        List<String> allowedRoots,
        List<String> watchDirectories,
        String reputationDatabasePath,
        boolean monitoringEnabled,
        boolean recursiveMonitoring,
        int maxMonitoringDepth,
        long maxFileSizeBytes,
        int maxFilesPerDirectoryScan,
        int maxDirectoryDepth) { }
