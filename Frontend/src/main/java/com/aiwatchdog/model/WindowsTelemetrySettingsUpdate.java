package com.aiwatchdog.model;

public record WindowsTelemetrySettingsUpdate(boolean enabled, Boolean scriptMonitoringEnabled, Boolean processMonitoringEnabled) {
    public WindowsTelemetrySettingsUpdate(boolean enabled) { this(enabled, null, null); }
}
