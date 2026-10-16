package com.aiwatchdog.backend.fileshield.config;

import java.util.List;

public record FileShieldSettingsResponse(
        boolean enabled,
        List<String> allowedRoots,
        List<String> watchDirectories,
        String reputationDatabasePath,
        boolean monitoringEnabled,
        boolean recursiveMonitoring,
        int maxMonitoringDepth,
        long maxFileSizeBytes,
        int maxFilesPerDirectoryScan,
        int maxDirectoryDepth,
        boolean watcherActive,
        boolean reputationDatabaseUsable,
        String reputationDatabaseMessage,
        String quarantineDirectory,
        List<com.aiwatchdog.backend.fileshield.reputation.ReputationProviderStatus> reputationProviders) {
    public FileShieldSettingsResponse(boolean enabled, List<String> allowedRoots, List<String> watchDirectories,
            String reputationDatabasePath, boolean monitoringEnabled, boolean recursiveMonitoring, int maxMonitoringDepth,
            long maxFileSizeBytes, int maxFilesPerDirectoryScan, int maxDirectoryDepth, boolean watcherActive,
            boolean reputationDatabaseUsable, String reputationDatabaseMessage) {
        this(enabled, allowedRoots, watchDirectories, reputationDatabasePath, monitoringEnabled, recursiveMonitoring,
                maxMonitoringDepth, maxFileSizeBytes, maxFilesPerDirectoryScan, maxDirectoryDepth, watcherActive,
                reputationDatabaseUsable, reputationDatabaseMessage, "", List.of());
    }
}
