package com.aiwatchdog.backend.fileshield.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Max;
import org.springframework.validation.annotation.Validated;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

@ConfigurationProperties(prefix = "ai-watchdog.file-shield")
@Validated
public class FileShieldProperties {
    private boolean enabled = true;
    private List<Path> allowedRoots = new ArrayList<>();
    @Min(1)
    private long maxFileSize = 100L * 1024 * 1024;
    @Min(1)
    private int maxFilesPerDirectoryScan = 500;
    @Min(0)
    private int maxDirectoryDepth = 5;
    private Path reputationDatabasePath = Path.of("file_reputation.db");
    private boolean threatIntelEnabled;
    private String threatIntelEndpoint = "";
    private String threatIntelApiKey = "";
    @Min(250) @Max(30000)
    private int threatIntelTimeoutMs = 3000;
    @Min(1) @Max(86400)
    private int threatIntelCacheTtlSeconds = 300;
    @Min(1) @Max(10000)
    private int threatIntelRequestsPerMinute = 30;
    private boolean monitoringEnabled = false;
    private List<Path> watchDirectories = new ArrayList<>();
    private boolean recursiveMonitoring = true;
    @Min(0) @Max(20)
    private int maxMonitoringDepth = 5;
    @Min(1) @Max(16)
    private int monitoringWorkerCount = 2;
    @Min(1) @Max(10000)
    private int monitoringQueueCapacity = 128;
    @Min(50) @Max(5000)
    private long stabilityCheckIntervalMs = 250;
    @Min(2) @Max(20)
    private int stabilityCheckAttempts = 6;

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
    public List<Path> getAllowedRoots() { return allowedRoots; }
    public void setAllowedRoots(List<Path> allowedRoots) { this.allowedRoots = allowedRoots == null ? new ArrayList<>() : new ArrayList<>(allowedRoots); }
    public long getMaxFileSize() { return maxFileSize; }
    public void setMaxFileSize(long maxFileSize) { this.maxFileSize = maxFileSize; }
    public int getMaxFilesPerDirectoryScan() { return maxFilesPerDirectoryScan; }
    public void setMaxFilesPerDirectoryScan(int value) { this.maxFilesPerDirectoryScan = value; }
    public int getMaxDirectoryDepth() { return maxDirectoryDepth; }
    public void setMaxDirectoryDepth(int value) { this.maxDirectoryDepth = value; }
    public Path getReputationDatabasePath() { return reputationDatabasePath; }
    public void setReputationDatabasePath(Path path) { this.reputationDatabasePath = path; }
    public boolean isThreatIntelEnabled() { return threatIntelEnabled; }
    public void setThreatIntelEnabled(boolean enabled) { this.threatIntelEnabled = enabled; }
    public String getThreatIntelEndpoint() { return threatIntelEndpoint; }
    public void setThreatIntelEndpoint(String endpoint) { this.threatIntelEndpoint = endpoint == null ? "" : endpoint.trim(); }
    public String getThreatIntelApiKey() { return threatIntelApiKey; }
    public void setThreatIntelApiKey(String apiKey) { this.threatIntelApiKey = apiKey == null ? "" : apiKey; }
    public int getThreatIntelTimeoutMs() { return threatIntelTimeoutMs; }
    public void setThreatIntelTimeoutMs(int value) { this.threatIntelTimeoutMs = Math.max(250, Math.min(30000, value)); }
    public int getThreatIntelCacheTtlSeconds() { return threatIntelCacheTtlSeconds; }
    public void setThreatIntelCacheTtlSeconds(int value) { this.threatIntelCacheTtlSeconds = Math.max(1, Math.min(86400, value)); }
    public int getThreatIntelRequestsPerMinute() { return threatIntelRequestsPerMinute; }
    public void setThreatIntelRequestsPerMinute(int value) { this.threatIntelRequestsPerMinute = Math.max(1, Math.min(10000, value)); }
    public boolean isMonitoringEnabled() { return monitoringEnabled; }
    public void setMonitoringEnabled(boolean enabled) { this.monitoringEnabled = enabled; }
    public List<Path> getWatchDirectories() { return watchDirectories; }
    public void setWatchDirectories(List<Path> directories) { this.watchDirectories = directories == null ? new ArrayList<>() : new ArrayList<>(directories); }
    public boolean isRecursiveMonitoring() { return recursiveMonitoring; }
    public void setRecursiveMonitoring(boolean recursive) { this.recursiveMonitoring = recursive; }
    public int getMaxMonitoringDepth() { return maxMonitoringDepth; }
    public void setMaxMonitoringDepth(int depth) { this.maxMonitoringDepth = depth; }
    public int getMonitoringWorkerCount() { return monitoringWorkerCount; }
    public void setMonitoringWorkerCount(int count) { this.monitoringWorkerCount = count; }
    public int getMonitoringQueueCapacity() { return monitoringQueueCapacity; }
    public void setMonitoringQueueCapacity(int capacity) { this.monitoringQueueCapacity = capacity; }
    public long getStabilityCheckIntervalMs() { return stabilityCheckIntervalMs; }
    public void setStabilityCheckIntervalMs(long intervalMs) { this.stabilityCheckIntervalMs = intervalMs; }
    public int getStabilityCheckAttempts() { return stabilityCheckAttempts; }
    public void setStabilityCheckAttempts(int attempts) { this.stabilityCheckAttempts = attempts; }
}
