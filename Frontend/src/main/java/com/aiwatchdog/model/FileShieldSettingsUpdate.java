package com.aiwatchdog.model;

import java.util.List;

public record FileShieldSettingsUpdate(
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
