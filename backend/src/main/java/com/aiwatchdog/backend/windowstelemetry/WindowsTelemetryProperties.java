package com.aiwatchdog.backend.windowstelemetry;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "ai-watchdog.windows-telemetry")
public class WindowsTelemetryProperties {
    /** Collection is opt-in; no Windows audit or Defender policy is changed by this application. */
    private boolean enabled;
    private boolean scriptMonitoringEnabled;
    private boolean processMonitoringEnabled;
    private int queueCapacity = 256;
    private long restartDelayMs = 5000;

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
    public boolean isScriptMonitoringEnabled() { return scriptMonitoringEnabled; }
    public void setScriptMonitoringEnabled(boolean enabled) { this.scriptMonitoringEnabled = enabled; }
    public boolean isProcessMonitoringEnabled() { return processMonitoringEnabled; }
    public void setProcessMonitoringEnabled(boolean enabled) { this.processMonitoringEnabled = enabled; }
    public int getQueueCapacity() { return queueCapacity; }
    public void setQueueCapacity(int queueCapacity) { this.queueCapacity = Math.max(16, Math.min(4096, queueCapacity)); }
    public long getRestartDelayMs() { return restartDelayMs; }
    public void setRestartDelayMs(long restartDelayMs) { this.restartDelayMs = Math.max(1000, Math.min(60000, restartDelayMs)); }
}
