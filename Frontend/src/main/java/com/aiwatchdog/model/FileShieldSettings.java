package com.aiwatchdog.model;

import java.util.List;

public record FileShieldSettings(
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
        List<ReputationProviderStatus> reputationProviders,
        long reputationEntryCount) {
    public FileShieldSettings {
        allowedRoots = allowedRoots == null ? List.of() : List.copyOf(allowedRoots);
        watchDirectories = watchDirectories == null ? List.of() : List.copyOf(watchDirectories);
        reputationProviders = reputationProviders == null ? List.of() : List.copyOf(reputationProviders);
    }
    public FileShieldSettings(boolean enabled, List<String> allowedRoots, List<String> watchDirectories,
            String reputationDatabasePath, boolean monitoringEnabled, boolean recursiveMonitoring, int maxMonitoringDepth,
            long maxFileSizeBytes, int maxFilesPerDirectoryScan, int maxDirectoryDepth, boolean watcherActive,
            boolean reputationDatabaseUsable, String reputationDatabaseMessage, String quarantineDirectory,
            List<ReputationProviderStatus> reputationProviders) {
        this(enabled, allowedRoots, watchDirectories, reputationDatabasePath, monitoringEnabled, recursiveMonitoring,
                maxMonitoringDepth, maxFileSizeBytes, maxFilesPerDirectoryScan, maxDirectoryDepth, watcherActive,
                reputationDatabaseUsable, reputationDatabaseMessage, quarantineDirectory, reputationProviders, 0);
    }
    public record ReputationProviderStatus(String provider, String state, String errorCategory, String lastCheckedAt) { }
}
