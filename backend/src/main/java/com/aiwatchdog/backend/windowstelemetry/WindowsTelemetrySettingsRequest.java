package com.aiwatchdog.backend.windowstelemetry;

public record WindowsTelemetrySettingsRequest(Boolean enabled, Boolean scriptMonitoringEnabled, Boolean processMonitoringEnabled) {
    public WindowsTelemetrySettingsRequest(Boolean enabled) { this(enabled, null, null); }
}
